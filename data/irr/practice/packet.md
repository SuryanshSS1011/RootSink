# Chain-label annotation packet

*Generated from release e7a56d7b0808, the audit snapshot (PREREGISTRATION PR-9, 2026-10-21).*

## What you are asked to do

Each item is one crash from a C/C++ project: the sanitizer report from running the crashing
input on the vulnerable revision, the developer's fix, and the code sites the pipeline recorded.
Read it, then fill one row of the sheet (`sheet_template.csv`). You do not see the dataset's
labels. Please do not look the item up, discuss it with the other annotator, or ask an AI tool.
Expect about 4-5 minutes per item once you are used to the format, so plan several sittings.

A *chain* is two weaknesses (MITRE CWE terminology, primary to resultant): a **source**, the
earlier weakness that makes the crash possible, and a **sink**, the weakness the crash itself
is. Example: a missing length check (CWE-20) lets a copy run past a buffer (CWE-787).

## The six answers

- `sink_cwe`: what weakness is the crash itself? Judge from the sanitizer report. Answer a
  CWE id from the list below, `other:<id>`, or `unclear`.
- `source_cwe`: what earlier weakness does the fix remove? Ask what the fix *enforces*. Same
  answers.
- `sink_site`: which numbered site is where the crash happens? A site number, or `none`.
- `source_site`: where is the source weakness? A site number, or `other:<file>:<function>` if it
  is in a function none of the listed sites is in, or `none`, or `unclear`. Answer at the level of
  the function; the exact line does not need to match.
- `site_roles`: give every listed site one role, as `1:defect;2:crash`. The roles are:
  - `defect`: the weakness itself is here, meaning the check that is missing or wrong, the
    computation that goes wrong, the variable or buffer that is created without being
    initialised, or the free that leaves a pointer dangling.
  - `repair`: the weakness is not here, but a change here would remove its cause for every input
    that reaches this path. A caller that validates a length before passing it on is an example.
  - `crash`: the crash happens here, and a change here would only stop the symptom, for example
    a check placed directly on the failing access.
  - `unrelated`: none of the above.
  - `unclear`: you cannot tell from the packet.
- `causal`: had the fix's check been in place, would this input have been stopped before the
  crash? `y`, `n`, or `unclear`.

Use `unclear` whenever the evidence does not let you decide. It is a valid answer, and a guess
is worse. Use the `note` column for anything that would help explain your answer.

Rules of thumb:
- The sink comes from the report: its error class and READ/WRITE line. The source comes from
  the fix: what condition it adds or what it changes.
- If the fix only adds a check exactly at the crashing access, with no earlier cause visible,
  choose the most specific source cue that fits.
- Ignore whitespace, comments, tests and build changes in the diff.
- An origin site (where a value was created or memory freed) is the `defect` only if the
  weakness is there, for example a declaration that should initialise. If the value should have
  been written later on another path, the origin is `unrelated` or `repair`, and the defect is
  where that write is missing.

Conventions of this dataset (declared modelling choices, so please follow them):
- A use-after-free is recorded as source **416** and sink **125** (if the freed memory is read)
  or **787** (if it is written). The freed-pointer reuse is what enables the access.
- A use of uninitialised memory is recorded as source **456** and sink **457**.
- A NULL dereference that crashes at the dereference itself is **476** as the sink.

## Answer vocabulary

Source:
- **20** Improper Input Validation: the fix validates an input-derived value (length, size, count, format) before use
- **129** Improper Validation of Array Index: the fix bounds-checks an array index specifically
- **190** Integer Overflow or Wraparound: the fix stops an arithmetic result wrapping (overflow-checked add/mul, wider type)
- **252** Unchecked Return Value: the fix checks a function's return value that was ignored
- **362** Concurrent Execution using Shared Resource with Improper Synchronization: the fix adds locking/synchronisation around shared state
- **416** Use After Free: the fix stops memory being used after it is freed (lifetime, refcount, dangling ptr)
- **456** Missing Initialization of a Variable: the fix initialises a variable or buffer that could be read uninitialised
- **476** NULL Pointer Dereference: the fix adds a NULL check before a dereference
- **843** Access of Resource Using Incompatible Type (Type Confusion): the fix checks an object's type/tag before treating it as that type

Sink:
- **119** Improper Restriction of Operations within Bounds of a Memory Buffer: out-of-bounds access whose direction the report does not give
- **125** Out-of-bounds Read: out-of-bounds READ (the report says READ, e.g. heap-buffer-overflow READ)
- **787** Out-of-bounds Write: out-of-bounds WRITE (the report says WRITE)
- **190** Integer Overflow or Wraparound: the report itself is an integer overflow (UBSan 'signed integer overflow')
- **415** Double Free: double free
- **416** Use After Free: use of freed memory, only if the read/write convention below cannot apply
- **457** Use of Uninitialized Variable: use of an uninitialised value (MemorySanitizer use-of-uninitialized-value)
- **476** NULL Pointer Dereference: NULL pointer dereference (SEGV on a near-zero address)


---

## Item 1

Project: ghostpdl (C++)

### Sanitizer report (vulnerable revision)

```
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x62a00010712c at pc 0x000000bfa663 bp 0x7fff518e6e30 sp 0x7fff518e6e28
READ of size 2 at 0x62a00010712c thread T0
SCARINESS: 24 (2-byte-read-heap-buffer-overflow-far-from-bounds)
    #0 0xbfa662 in mem_mono_copy_mono /src/ghostpdl/./base/gdevm1.c:683:17
    #1 0xbfdf76 in mem_mapped4_copy_color /src/ghostpdl/./base/gdevm4.c:229:12
    #2 0x10b95ea in tile_clip_copy_color /src/ghostpdl/./base/gxclip2.c:301:24
    #3 0x588972 in tile_colored_fill /src/ghostpdl/./base/gxp1fill.c:269:20
    #4 0x587b73 in tile_by_steps /src/ghostpdl/./base/gxp1fill.c:237:24
    #5 0x5860e4 in gx_dc_pattern_fill_rectangle /src/ghostpdl/./base/gxp1fill.c:395:20
    #6 0xadafed in gx_dc_default_fill_masked /src/ghostpdl/./base/gxdcolor.c:1109:20
    #7 0xbb38a4 in gx_default_fill_mask /src/ghostpdl/./base/gdevdbit.c:584:16
    #8 0xb4b76e in gx_image_fill_masked /src/ghostpdl/./base/gximask.c:115:16
    #9 0x119da51 in clist_playback_band /src/ghostpdl/./base/gxclrast.c:2306:28
    #10 0x69035c in clist_playback_file_bands /src/ghostpdl/./base/gxclread.c:1035:16
    #11 0x6949b0 in clist_render_rectangle /src/ghostpdl/./base/gxclread.c:969:16
    #12 0x693d8a in clist_rasterize_lines /src/ghostpdl/./base/gxclread.c:858:20
    #13 0x692f4f in clist_get_bits_rectangle /src/ghostpdl/./base/gxclread.c:747:12
    #14 0x66752a in gdev_prn_get_bits /src/ghostpdl/./base/gdevprn.c:1636:12
    #15 0x7ee534 in cups_print_chunked /src/ghostpdl/./cups/gdevcups.c:4849:9
    #16 0x7dce1b in cups_print_pages /src/ghostpdl/./cups/gdevcups.c
    #17 0x6633b9 in gdev_prn_output_page_aux /src/ghostpdl/./base/gdevprn.c:1049:27
    #18 0x662675 in gdev_prn_output_page /src/ghostpdl/./base/gdevprn.c:1085:12
    #19 0x7edce9 in cups_output_page /src/ghostpdl/./cups/gdevcups.c:2826:15
    #20 0x8a8b4f in gs_output_page /src/ghostpdl/./base/gsdevice.c:207:17
    #21 0xdcd9e2 in zoutputpage /src/ghostpdl/./psi/zdevice.c:416:12
    #22 0xcfc8ac in interp /src/ghostpdl/./psi/interp.c:1351:28
    #23 0xcfc8ac in gs_call_interp /src/ghostpdl/./psi/interp.c:522:12
    #24 0xcfc8ac in gs_interpret /src/ghostpdl/./psi/interp.c:479:12
    #25 0x56912a in gs_main_interpret /src/ghostpdl/./psi/imain.c:257:12
    #26 0x56912a in gs_main_run_string_end /src/ghostpdl/./psi/imain.c:945:12
    #27 0x56912a in gs_main_run_string_with_length /src/ghostpdl/./psi/imain.c:889:12
    #28 0x5645d2 in gs_main_run_string /src/ghostpdl/./psi/imain.c:870:12
    #29 0x101dad1 in run_string /src/ghostpdl/./psi/imainarg.c:1166:12
    #30 0x1019b09 in swproc /src/ghostpdl/./psi/imainarg.c:367:20
    #31 0x10169ee in gs_main_init_with_args01 /src/ghostpdl/./psi/imainarg.c:224:24
    #32 0x101d859 in gs_main_init_with_args /src/ghostpdl/./psi/imainarg.c:289:16
    #33 0xce8394 in psapi_init_with_args /src/ghostpdl/./psi/psapi.c:281:12
    #34 0x560ae0 in gsapi_init_with_args /src/ghostpdl/./psi/iapi.c:247:12
    #35 0x55fcb0 in gs_to_raster_fuzz /src/gstoraster_fuzzer.cc:97:8
    #36 0x55fcb0 in LLVMFuzzerTestOneInput /src/gstoraster_fuzzer.cc:114:2
```

### Fix diff (whitespace-only hunks removed; first 200 lines)

```diff
diff --git a/base/gsptype1.c b/base/gsptype1.c
@@ -1,4 +1,4 @@
-/* Copyright (C) 2001-2021 Artifex Software, Inc.
+/* Copyright (C) 2001-2022 Artifex Software, Inc.
    All Rights Reserved.
 
    This software is provided AS-IS with no warranty, either express or
@@ -616,10 +616,34 @@ compute_inst_matrix(gs_pattern1_instance_t * pinst,
         return code;
 
     /* The stepping matrix : */
-    xx = pinst->templat.XStep * saved->ctm.xx;
-    xy = pinst->templat.XStep * saved->ctm.xy;
-    yx = pinst->templat.YStep * saved->ctm.yx;
-    yy = pinst->templat.YStep * saved->ctm.yy;
+    /* We do not want to overflow the maths here. Since xx etc are all floats
+     * then the multiplication will definitely fit into a double, and we can
+     * check to ensure that the result still fits into a float without
+     * overflowing at any point.
+     */
+    {
+        double double_mult = 0.0;
+
+        double_mult = (double)pinst->templat.XStep * (double)saved->ctm.xx;
+        if (double_mult < -MAX_FLOAT || double_mult > MAX_FLOAT)
+            return_error(gs_error_rangecheck);
+        xx = (float)double_mult;
+
+        double_mult = (double)pinst->templat.XStep * (double)saved->ctm.xy;
+        if (double_mult < -MAX_FLOAT || double_mult > MAX_FLOAT)
+            return_error(gs_error_rangecheck);
+        xy = double_mult;
+
+        double_mult = (double)pinst->templat.YStep * (double)saved->ctm.yx;
+        if (double_mult < -MAX_FLOAT || double_mult > MAX_FLOAT)
+            return_error(gs_error_rangecheck);
+        yx = double_mult;
+
+        double_mult = (double)pinst->templat.YStep * (double)saved->ctm.yy;
+        if (double_mult < -MAX_FLOAT || double_mult > MAX_FLOAT)
+            return_error(gs_error_rangecheck);
+        yy = double_mult;
+    }
 
     /* Adjust the stepping matrix so all coefficients are >= 0. */
     if (xx == 0 || yy == 0) { /* We know that both xy and yx are non-zero. */
diff --git a/pdf/pdf_pattern.c b/pdf/pdf_pattern.c
@@ -1,4 +1,4 @@
-/* Copyright (C) 2019-2021 Artifex Software, Inc.
+/* Copyright (C) 2019-2022 Artifex Software, Inc.
    All Rights Reserved.
 
    This software is provided AS-IS with no warranty, either express or
@@ -446,6 +446,14 @@ pdfi_setpattern_type1(pdf_context *ctx, pdf_dict *stream_dict, pdf_dict *page_di
     if (code < 0)
         goto exit;
 
+    /* The pattern instance holds the pattern step as floats, make sure they
+     * will fit.
+     */
+    if (XStep < -MAX_FLOAT || XStep > MAX_FLOAT || YStep < -MAX_FLOAT || YStep > MAX_FLOAT) {
+        code = gs_note_error(gs_error_rangecheck);
+        goto exit;
+    }
+
     /* The spec says Resources are required, but in fact this doesn't seem to be true.
      * (tests_private/pdf/sumatra/infinite_pattern_recursion.pdf)
      */
-- 
2.55.0
```

### Sites recorded by the pipeline (unlabelled)

1. /src/ghostpdl/./base/gdevm1.c:683 (mem_mono_copy_mono)
2. base/gsptype1.c:623 (compute_inst_matrix)

---

## Item 2

Project: hunspell (C++)

### Sanitizer report (vulnerable revision)

```
==4105188==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f2 at pc 0x0000005bbc02 bp 0x7fffe13fed10 sp 0x7fffe13fed08
READ of size 2 at 0x6020000000f2 thread T0
SCARINESS: 14 (2-byte-read-heap-buffer-overflow)
    #0 0x5bbc01 in SuggestMgr::badcharkey_utf(std::__1::vector<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::allocator<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >&, w_char const*, int, int) /src/hunspell/src/hunspell/suggestmgr.cxx:622:29
    #1 0x5b44ed in SuggestMgr::suggest(std::__1::vector<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::allocator<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >&, char const*, int*) /src/hunspell/src/hunspell/suggestmgr.cxx:274:9
    #2 0x584039 in HunspellImpl::suggest_internal(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&, bool&, unsigned long&, int&) /src/hunspell/src/hunspell/hunspell.cxx:1051:22
    #3 0x5811ff in HunspellImpl::suggest(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&) /src/hunspell/src/hunspell/hunspell.cxx:882:35
    #4 0x5a461a in Hunspell::suggest(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&) /src/hunspell/src/hunspell/hunspell.cxx:2043:18
    #5 0x56e24e in LLVMFuzzerTestOneInput /src/hunspell/./src/tools/affdicfuzzer.cxx:66:14
    #6 0x43ec23 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #7 0x42a382 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:324:6
    #8 0x42fc2c in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:860:9
    #9 0x459162 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #10 0x14f881edd082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 1878e6b475720c7c51969e69ab2d276fae6d1dee)
    #11 0x42054d in _start (/out/affdicfuzzer+0x42054d)

DEDUP_TOKEN: SuggestMgr::badcharkey_utf(std::__1::vector<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::allocator<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >&, w_char const*, int, int)--SuggestMgr::suggest(std::__1::vector<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::allocator<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >&, char const*, int*)--HunspellImpl::suggest_internal(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&, bool&, unsigned long&, int&)
0x6020000000f2 is located 0 bytes to the right of 2-byte region [0x6020000000f0,0x6020000000f2)
allocated by thread T0 here:
    #0 0x56abfd in operator new(unsigned long) /src/llvm-project/compiler-rt/lib/asan/asan_new_delete.cpp:95:3
    #1 0x658385 in __libcpp_operator_new<unsigned long> /usr/local/bin/../include/c++/v1/new:245:10
    #2 0x658385 in __libcpp_allocate /usr/local/bin/../include/c++/v1/new:271:10
    #3 0x658385 in allocate /usr/local/bin/../include/c++/v1/__memory/allocator.h:105:38
    #4 0x658385 in allocate /usr/local/bin/../include/c++/v1/__memory/allocator_traits.h:262:20
    #5 0x658385 in __split_buffer /usr/local/bin/../include/c++/v1/__split_buffer:306:29
    #6 0x658385 in std::__1::vector<w_char, std::__1::allocator<w_char> >::__append(unsigned long) /usr/local/bin/../include/c++/v1/vector:1031:53
    #7 0x64ba34 in resize /usr/local/bin/../include/c++/v1/vector:1902:15
    #8 0x64ba34 in u8_u16(std::__1::vector<w_char, std::__1::allocator<w_char> >&, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&, bool) /src/hunspell/src/hunspell/csutil.cxx:176:8
    #9 0x5b045c in SuggestMgr::SuggestMgr(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&, unsigned int, AffixMgr*) /src/hunspell/src/hunspell/suggestmgr.cxx:122:15
    #10 0x573192 in HunspellImpl::HunspellImpl(char const*, char const*, char const*) /src/hunspell/src/hunspell/hunspell.cxx:197:15
    #11 0x5a44ae in Hunspell::Hunspell(char const*, char const*, char const*) /src/hunspell/src/hunspell/hunspell.cxx:2026:16
    #12 0x56e20f in LLVMFuzzerTestOneInput /src/hunspell/./src/tools/affdicfuzzer.cxx:63:14
    #13 0x43ec23 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #14 0x42a382 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:324:6
    #15 0x42fc2c in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:860:9
    #16 0x459162 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #17 0x14f881edd082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 1878e6b475720c7c51969e69ab2d276fae6d1dee)

DEDUP_TOKEN: operator new(unsigned long)--__libcpp_operator_new<unsigned long>--__libcpp_allocate
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/hunspell/src/hunspell/suggestmgr.cxx:622:29 in SuggestMgr::badcharkey_utf(std::__1::vector<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::allocator<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >&, w_char const*, int, int)
```

### Fix diff (whitespace-only hunks removed; first 200 lines)

```diff
diff --git a/src/hunspell/suggestmgr.cxx b/src/hunspell/suggestmgr.cxx
@@ -119,7 +119,10 @@ SuggestMgr::SuggestMgr(const std::string& tryme, unsigned int maxn, AffixMgr* ap
 
   if (!ckey.empty()) {
     if (utf8) {
-      ckeyl = u8_u16(ckey_utf, ckey);
+      int len = u8_u16(ckey_utf, ckey);
+      if (len != -1) {
+        ckeyl = len;
+      }
     } else {
       ckeyl = ckey.size();
     }
@@ -128,7 +131,10 @@ SuggestMgr::SuggestMgr(const std::string& tryme, unsigned int maxn, AffixMgr* ap
   ctry = tryme;
   if (!ctry.empty()) {
     if (utf8) {
-      ctryl = u8_u16(ctry_utf, ctry);
+      int len = u8_u16(ctry_utf, ctry);
+      if (len != -1) {
+        ctryl = len;
+      }
     } else {
       ctryl = ctry.size();
     }
```

### Sites recorded by the pipeline (unlabelled)

1. src/hunspell/suggestmgr.cxx:123 (SuggestMgr)
2. src/hunspell/suggestmgr.cxx:622 (SuggestMgr::badcharkey_utf(std::__1::vector<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::allocator<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >&, w_char const*, int, int))

---

## Item 3

Project: openvswitch (C++)

### Sanitizer report (vulnerable revision)

```
==2805822==ERROR: AddressSanitizer: attempting double-free on 0x603000000040 in thread T0:
SCARINESS: 42 (double-free)
    #0 0x4ed7f0 in free /src/llvm/projects/compiler-rt/lib/asan/asan_malloc_linux.cc:124
    #1 0x5a5cea in minimatch_destroy /src/openvswitch/lib/match.c:1783:5
    #2 0x52e427 in ofctl_parse_flow /src/openvswitch/tests/oss-fuzz/ofctl_parse_target.c:65:9
    #3 0x52e290 in LLVMFuzzerTestOneInput /src/openvswitch/tests/oss-fuzz/ofctl_parse_target.c:107:5
    #4 0x52e98a in ExecuteFilesOnyByOne(int, char**) /src/libfuzzer/afl/afl_driver.cpp:301:5
    #5 0x52eeee in main /src/libfuzzer/afl/afl_driver.cpp:339:12
    #6 0x14ef337c582f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #7 0x41ee68 in _start (/out/ofctl_parse_target+0x41ee68)

DEDUP_TOKEN: free--minimatch_destroy--ofctl_parse_flow
0x603000000040 is located 0 bytes inside of 32-byte region [0x603000000040,0x603000000060)
freed by thread T0 here:
    #0 0x4ed7f0 in free /src/llvm/projects/compiler-rt/lib/asan/asan_malloc_linux.cc:124
    #1 0x5a5cea in minimatch_destroy /src/openvswitch/lib/match.c:1783:5
    #2 0x52e41b in ofctl_parse_flow /src/openvswitch/tests/oss-fuzz/ofctl_parse_target.c:64:9
    #3 0x52e290 in LLVMFuzzerTestOneInput /src/openvswitch/tests/oss-fuzz/ofctl_parse_target.c:107:5
    #4 0x52e98a in ExecuteFilesOnyByOne(int, char**) /src/libfuzzer/afl/afl_driver.cpp:301:5
    #5 0x52eeee in main /src/libfuzzer/afl/afl_driver.cpp:339:12
    #6 0x14ef337c582f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)

DEDUP_TOKEN: free--minimatch_destroy--ofctl_parse_flow
previously allocated by thread T0 here:
    #0 0x4edbbf in __interceptor_malloc /src/llvm/projects/compiler-rt/lib/asan/asan_malloc_linux.cc:146
    #1 0x615706 in xmalloc /src/openvswitch/lib/util.c:123:15
    #2 0x63e910 in miniflow_alloc /src/openvswitch/lib/flow.c:3260:28
    #3 0x5a58f8 in minimatch_init /src/openvswitch/lib/match.c:1737:5
    #4 0x5b30f3 in parse_ofp_str__ /src/openvswitch/lib/ofp-flow.c:1759:5
    #5 0x5ac9cd in parse_ofp_str /src/openvswitch/lib/ofp-flow.c:1790:13
    #6 0x5b39ad in parse_ofp_flow_mod_str /src/openvswitch/lib/ofp-flow.c:1817:19
    #7 0x52e3c4 in ofctl_parse_flow /src/openvswitch/tests/oss-fuzz/ofctl_parse_target.c:58:13
    #8 0x52e290 in LLVMFuzzerTestOneInput /src/openvswitch/tests/oss-fuzz/ofctl_parse_target.c:107:5
    #9 0x52e98a in ExecuteFilesOnyByOne(int, char**) /src/libfuzzer/afl/afl_driver.cpp:301:5
    #10 0x52eeee in main /src/libfuzzer/afl/afl_driver.cpp:339:12
    #11 0x14ef337c582f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)

DEDUP_TOKEN: __interceptor_malloc--xmalloc--miniflow_alloc
SUMMARY: AddressSanitizer: double-free /src/llvm/projects/compiler-rt/lib/asan/asan_malloc_linux.cc:124 in free
==2805822==ABORTING
```

### Fix diff (whitespace-only hunks removed; first 200 lines)

```diff
diff --git a/tests/oss-fuzz/ofctl_parse_target.c b/tests/oss-fuzz/ofctl_parse_target.c
@@ -22,7 +22,7 @@ ofctl_parse_flows__(struct ofputil_flow_mod *fms, size_t n_fms,
 
     if (!(usable_protocols & OFPUTIL_P_ANY)) {
         printf("no usable protocol\n");
-        return;
+        goto free;
     }
     for (i = 0; i < sizeof(enum ofputil_protocol) * CHAR_BIT; i++) {
         protocol = 1u << i;
@@ -40,7 +40,11 @@ ofctl_parse_flows__(struct ofputil_flow_mod *fms, size_t n_fms,
 
         msg = ofputil_encode_flow_mod(fm, protocol);
         ofpbuf_delete(msg);
+    }
 
+free:
+    for (i = 0; i < n_fms; i++) {
+        struct ofputil_flow_mod *fm = &fms[i];
         free(CONST_CAST(struct ofpact *, fm->ofpacts));
         minimatch_destroy(&fm->match);
     }
@@ -62,7 +66,6 @@ ofctl_parse_flow(const char *input, int command)
         free(error);
     } else {
         ofctl_parse_flows__(&fm, 1, usable_protocols);
-        minimatch_destroy(&fm.match);
     }
 }
 
```

### Sites recorded by the pipeline (unlabelled)

1. lib/match.c:1783 (minimatch_destroy)

---

## Item 4

Project: aom (C++)

### Sanitizer report (vulnerable revision)

```
==458677==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6190000004b4 at pc 0x0000005c3ede bp 0x7ffdb36a9550 sp 0x7ffdb36a9548
WRITE of size 1 at 0x6190000004b4 thread T0
SCARINESS: 41 (1-byte-write-heap-buffer-overflow-far-from-bounds)
    #0 0x5c3edd in intra_copy_frame_mvs /src/aom/av1/decoder/decodemv.c:1558:21
    #1 0x5c3edd in av1_read_mode_info /src/aom/av1/decoder/decodemv.c:1575:7
    #2 0x5ac3fc in decode_mbmi_block /src/aom/av1/decoder/decodeframe.c:376:3
    #3 0x5ac3fc in parse_decode_block /src/aom/av1/decoder/decodeframe.c:1121:3
    #4 0x5a7fba in decode_partition /src/aom/av1/decoder/decodeframe.c:1328:26
    #5 0x59abfa in parse_tile_row_mt /src/aom/av1/decoder/decodeframe.c:3143:7
    #6 0x59abfa in row_mt_worker_hook /src/aom/av1/decoder/decodeframe.c:3216:7
    #7 0x87b2b1 in execute /src/aom/aom_util/aom_thread.c:163:27
    #8 0x58fe3e in launch_dec_workers /src/aom/av1/decoder/decodeframe.c
    #9 0x58fe3e in decode_tiles_row_mt /src/aom/av1/decoder/decodeframe.c:3819:3
    #10 0x58fe3e in av1_decode_tg_tiles_and_wrapup /src/aom/av1/decoder/decodeframe.c:5246:9
    #11 0x609c1a in read_one_tile_group_obu /src/aom/av1/decoder/obu.c:361:3
    #12 0x609c1a in aom_decode_frame_from_obus /src/aom/av1/decoder/obu.c:1030:33
    #13 0x5e4649 in av1_receive_compressed_data /src/aom/av1/decoder/decoder.c:469:7
    #14 0x571ba3 in frame_worker_hook /src/aom/av1/av1_dx_iface.c:409:16
    #15 0x87b2b1 in execute /src/aom/aom_util/aom_thread.c:163:27
    #16 0x55fd3b in decode_one /src/aom/av1/av1_dx_iface.c:526:3
    #17 0x55fd3b in decoder_decode /src/aom/av1/av1_dx_iface.c:713:11
    #18 0x55e9e3 in aom_codec_decode /src/aom/aom/src/aom_decoder.c:103:11
    #19 0x55d1dd in LLVMFuzzerTestOneInput /src/aom/examples/av1_dec_fuzzer.cc:56:9
    #20 0x4551f3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #21 0x440e82 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:324:6
    #22 0x4466cc in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:860:9
    #23 0x46f2c2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #24 0x151485e76082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082)
    #25 0x41f6ad in _start (/out/av1_dec_fuzzer+0x41f6ad)

DEDUP_TOKEN: intra_copy_frame_mvs--av1_read_mode_info--decode_mbmi_block
0x6190000004b4 is located 165 bytes to the right of 911-byte region [0x619000000080,0x61900000040f)
allocated by thread T0 here:
    #0 0x523add in __interceptor_malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:129:3
    #1 0x879b28 in aom_memalign /src/aom/aom_mem/aom_mem.c:59:22
    #2 0x879b28 in aom_malloc /src/aom/aom_mem/aom_mem.c:67:40
    #3 0x879b28 in aom_calloc /src/aom/aom_mem/aom_mem.c:72:19
    #4 0x595b0d in ensure_mv_buffer /src/aom/av1/common/av1_common_int.h:1236:7
    #5 0x595b0d in resize_context_buffers /src/aom/av1/decoder/decodeframe.c:1918:3
    #6 0x5950cd in setup_frame_size /src/aom/av1/decoder/decodeframe.c:1974:3
```

### Fix diff (whitespace-only hunks removed; first 200 lines)

```diff
diff --git a/av1/common/av1_common_int.h b/av1/common/av1_common_int.h
@@ -1219,26 +1219,21 @@
   const int buf_cols = buf->mi_cols;
   const CommonModeInfoParams *const mi_params = &cm->mi_params;
 
-  if (buf->seg_map == NULL || buf_rows != mi_params->mi_rows ||
+  if (buf->mvs == NULL || buf_rows != mi_params->mi_rows ||
       buf_cols != mi_params->mi_cols) {
+    aom_free(buf->mvs);
     buf->mi_rows = mi_params->mi_rows;
     buf->mi_cols = mi_params->mi_cols;
+    CHECK_MEM_ERROR(cm, buf->mvs,
+                    (MV_REF *)aom_calloc(((mi_params->mi_rows + 1) >> 1) *
+                                             ((mi_params->mi_cols + 1) >> 1),
+                                         sizeof(*buf->mvs)));
     aom_free(buf->seg_map);
     CHECK_MEM_ERROR(
         cm, buf->seg_map,
         (uint8_t *)aom_calloc(mi_params->mi_rows * mi_params->mi_cols,
                               sizeof(*buf->seg_map)));
   }
-  if (buf->mvs == NULL || buf_rows != mi_params->mi_rows ||
-      buf_cols != mi_params->mi_cols) {
-    if (cm->seq_params->order_hint_info.enable_ref_frame_mvs) {
-      aom_free(buf->mvs);
-      CHECK_MEM_ERROR(cm, buf->mvs,
-                      (MV_REF *)aom_calloc(((mi_params->mi_rows + 1) >> 1) *
-                                               ((mi_params->mi_cols + 1) >> 1),
-                                           sizeof(*buf->mvs)));
-    }
-  }
 
   const int mem_size =
       ((mi_params->mi_rows + MAX_MIB_SIZE) >> 1) * (mi_params->mi_stride >> 1);
```

### Sites recorded by the pipeline (unlabelled)

1. av1/common/av1_common_int.h:1223 (None)
2. av1/decoder/decodemv.c:1558 (intra_copy_frame_mvs)

---

## Item 5

Project: linux-kernel (C)

### Sanitizer report (vulnerable revision)

```
[  426.189961][ T1883] BUG: KASAN: slab-use-after-free in io_poll_remove_entries.part.0+0x622/0x680
[  426.190809][ T1883] Write of size 8 at addr ffff8880268162e0 by task kworker/2:3/1883
[  426.191568][ T1883] 
[  426.191806][ T1883] CPU: 2 UID: 0 PID: 1883 Comm: kworker/2:3 Tainted: G    B               6.16.0-rc3-g631ae0c01010 #1 PREEMPT(full) 
[  426.191812][ T1883] Tainted: [B]=BAD_PAGE
[  426.191813][ T1883] Hardware name: Red Hat KVM, BIOS 1.16.0-4.module+el8.9.0+19570+14a90618 04/01/2014
[  426.191817][ T1883] Workqueue: events io_fallback_req_func
[  426.191822][ T1883] Call Trace:
[  426.191826][ T1883]  <TASK>
[  426.191829][ T1883]  dump_stack_lvl+0x78/0xe0
[  426.191836][ T1883]  print_report+0xcd/0x6a0
[  426.191842][ T1883]  ? io_poll_remove_entries.part.0+0x622/0x680
[  426.191844][ T1883]  ? __virt_addr_valid+0x22c/0x420
[  426.191849][ T1883]  ? io_poll_remove_entries.part.0+0x622/0x680
[  426.191851][ T1883]  kasan_report+0xe0/0x110
[  426.191855][ T1883]  ? io_poll_remove_entries.part.0+0x622/0x680
[  426.191858][ T1883]  io_poll_remove_entries.part.0+0x622/0x680
[  426.191862][ T1883]  io_poll_task_func+0x42d/0xdf0
[  426.191865][ T1883]  ? __pfx_io_poll_task_func+0x10/0x10
[  426.191868][ T1883]  ? find_held_lock+0x2b/0x80
[  426.191873][ T1883]  io_fallback_req_func+0x17d/0x540
[  426.191875][ T1883]  ? __pfx_io_fallback_req_func+0x10/0x10
[  426.191878][ T1883]  ? trace_lock_acquire+0x90/0xd0
[  426.191880][ T1883]  ? lock_acquire+0x30/0x80
[  426.191883][ T1883]  ? process_one_work+0x805/0x1860
[  426.191887][ T1883]  process_one_work+0x885/0x1860
[  426.191891][ T1883]  ? __pfx_process_one_work+0x10/0x10
[  426.191895][ T1883]  ? assign_work+0x167/0x240
[  426.191898][ T1883]  worker_thread+0x593/0xfb0
[  426.191901][ T1883]  ? lockdep_hardirqs_on+0x7c/0x110
[  426.191905][ T1883]  ? __kthread_parkme+0xc1/0x200
[  426.191909][ T1883]  ? __pfx_worker_thread+0x10/0x10
[  426.191912][ T1883]  kthread+0x36c/0x6b0
[  426.191915][ T1883]  ? __pfx_kthread+0x10/0x10
[  426.191917][ T1883]  ? rcu_is_watching+0x12/0xc0
[  426.191921][ T1883]  ? __pfx_kthread+0x10/0x10
[  426.191924][ T1883]  ret_from_fork+0x3bc/0x530
[  426.191928][ T1883]  ? __pfx_kthread+0x10/0x10
[  426.191931][ T1883]  ret_from_fork_asm+0x1a/0x30
[  426.191937][ T1883]  </TASK>
```

### Fix diff (whitespace-only hunks removed; first 200 lines)

```diff
diff --git a/drivers/comedi/comedi_fops.c b/drivers/comedi/comedi_fops.c
@@ -787,6 +787,7 @@ static int is_device_busy(struct comedi_device *dev)
 	struct comedi_subdevice *s;
 	int i;
 
+	lockdep_assert_held_write(&dev->attach_lock);
 	lockdep_assert_held(&dev->mutex);
 	if (!dev->attached)
 		return 0;
@@ -795,7 +796,16 @@ static int is_device_busy(struct comedi_device *dev)
 		s = &dev->subdevices[i];
 		if (s->busy)
 			return 1;
-		if (s->async && comedi_buf_is_mmapped(s))
+		if (!s->async)
+			continue;
+		if (comedi_buf_is_mmapped(s))
+			return 1;
+		/*
+		 * There may be tasks still waiting on the subdevice's wait
+		 * queue, although they should already be about to be removed
+		 * from it since the subdevice has no active async command.
+		 */
+		if (wq_has_sleeper(&s->async->wait_head))
 			return 1;
 	}
 
@@ -825,15 +835,22 @@ static int do_devconfig_ioctl(struct comedi_device *dev,
 		return -EPERM;
 
 	if (!arg) {
-		if (is_device_busy(dev))
-			return -EBUSY;
+		int rc = 0;
+
 		if (dev->attached) {
-			struct module *driver_module = dev->driver->module;
+			down_write(&dev->attach_lock);
+			if (is_device_busy(dev)) {
+				rc = -EBUSY;
+			} else {
+				struct module *driver_module =
+					dev->driver->module;
 
-			comedi_device_detach(dev);
-			module_put(driver_module);
+				comedi_device_detach_locked(dev);
+				module_put(driver_module);
+			}
+			up_write(&dev->attach_lock);
 		}
-		return 0;
+		return rc;
 	}
 
 	if (copy_from_user(&it, arg, sizeof(it)))
diff --git a/drivers/comedi/comedi_internal.h b/drivers/comedi/comedi_internal.h
@@ -50,6 +50,7 @@ extern struct mutex comedi_drivers_list_lock;
 int insn_inval(struct comedi_device *dev, struct comedi_subdevice *s,
 	       struct comedi_insn *insn, unsigned int *data);
 
+void comedi_device_detach_locked(struct comedi_device *dev);
 void comedi_device_detach(struct comedi_device *dev);
 int comedi_device_attach(struct comedi_device *dev,
 			 struct comedi_devconfig *it);
diff --git a/drivers/comedi/drivers.c b/drivers/comedi/drivers.c
@@ -158,7 +158,7 @@ static void comedi_device_detach_cleanup(struct comedi_device *dev)
 	int i;
 	struct comedi_subdevice *s;
 
-	lockdep_assert_held(&dev->attach_lock);
+	lockdep_assert_held_write(&dev->attach_lock);
 	lockdep_assert_held(&dev->mutex);
 	if (dev->subdevices) {
 		for (i = 0; i < dev->n_subdevices; i++) {
@@ -196,16 +196,23 @@ static void comedi_device_detach_cleanup(struct comedi_device *dev)
 	comedi_clear_hw_dev(dev);
 }
 
-void comedi_device_detach(struct comedi_device *dev)
+void comedi_device_detach_locked(struct comedi_device *dev)
 {
+	lockdep_assert_held_write(&dev->attach_lock);
 	lockdep_assert_held(&dev->mutex);
 	comedi_device_cancel_all(dev);
-	down_write(&dev->attach_lock);
 	dev->attached = false;
 	dev->detach_count++;
 	if (dev->driver)
 		dev->driver->detach(dev);
 	comedi_device_detach_cleanup(dev);
+}
+
+void comedi_device_detach(struct comedi_device *dev)
+{
+	lockdep_assert_held(&dev->mutex);
+	down_write(&dev->attach_lock);
+	comedi_device_detach_locked(dev);
 	up_write(&dev->attach_lock);
 }
 
-- 
cgit 1.3.1-korg
```

### Sites recorded by the pipeline (unlabelled)

1. io_uring/poll.c:146 (__raw_spin_lock_irq)

---

## Item 6

Project: wasm3 (C)

### Sanitizer report (vulnerable revision)

```
==615922==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000160 at pc 0x000000568696 bp 0x7ffff3245120 sp 0x7ffff3245118
WRITE of size 4 at 0x602000000160 thread T0
SCARINESS: 46 (4-byte-write-heap-buffer-overflow-far-from-bounds)
    #0 0x568695 in NewCodePage /src/wasm3/source/m3_code.c:27:29
    #1 0x560bac in AcquireCodePageWithCapacity /src/wasm3/source/m3_env.c:990:20
    #2 0x5a8f4d in EnsureCodePageNumLines /src/wasm3/source/m3_emit.c:21:28
    #3 0x576f6b in Compile_BranchTable /src/wasm3/source/m3_compile.c:1342:1
    #4 0x5a25fa in CompileBlockStatements /src/wasm3/source/m3_compile.c:2270:1
    #5 0x5a3db4 in CompileFunction /src/wasm3/source/m3_compile.c:2458:1
    #6 0x55d1bc in m3_FindFunction /src/wasm3/source/m3_env.c:686:1
    #7 0x556e2f in LLVMFuzzerTestOneInput /src/wasm3/platforms/app_fuzz/fuzzer.c:33:30
    #8 0x459c43 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:599:15
    #9 0x443a52 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:6
    #10 0x44989a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:856:9
    #11 0x475582 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #12 0x14f8cb77083f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2083f)
    #13 0x41e738 in _start (/out/fuzzer+0x41e738)

DEDUP_TOKEN: NewCodePage--AcquireCodePageWithCapacity--EnsureCodePageNumLines
0x602000000160 is located 15 bytes to the right of 1-byte region [0x602000000150,0x602000000151)
allocated by thread T0 here:
    #0 0x523712 in calloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:154:3
    #1 0x568611 in NewCodePage /src/wasm3/source/m3_code.c:23:25
    #2 0x560bac in AcquireCodePageWithCapacity /src/wasm3/source/m3_env.c:990:20
    #3 0x5a8f4d in EnsureCodePageNumLines /src/wasm3/source/m3_emit.c:21:28
    #4 0x576f6b in Compile_BranchTable /src/wasm3/source/m3_compile.c:1342:1
    #5 0x5a25fa in CompileBlockStatements /src/wasm3/source/m3_compile.c:2270:1
    #6 0x5a3db4 in CompileFunction /src/wasm3/source/m3_compile.c:2458:1
    #7 0x55d1bc in m3_FindFunction /src/wasm3/source/m3_env.c:686:1
    #8 0x556e2f in LLVMFuzzerTestOneInput /src/wasm3/platforms/app_fuzz/fuzzer.c:33:30
    #9 0x459c43 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:599:15
    #10 0x443a52 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:6
    #11 0x44989a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:856:9
    #12 0x475582 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #13 0x14f8cb77083f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2083f)

DEDUP_TOKEN: calloc--NewCodePage--AcquireCodePageWithCapacity
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/wasm3/source/m3_code.c:27:29 in NewCodePage
Shadow bytes around the buggy address:
  0x0c047fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

### Fix diff (whitespace-only hunks removed; first 200 lines)

```diff
diff --git a/source/m3_code.c b/source/m3_code.c
@@ -5,6 +5,7 @@
 //  Copyright © 2019 Steven Massey. All rights reserved.
 //
 
+#include <limits.h>
 #include "m3_code.h"
 #include "m3_env.h"
 
@@ -15,9 +16,23 @@ IM3CodePage  NewCodePage  (IM3Runtime i_runtime, u32 i_minNumLines)
 {
     IM3CodePage page;
 
+    // check multiplication overflow
+    if (i_minNumLines > UINT_MAX / sizeof (code_t)) {
+        return NULL;
+    }
     u32 pageSize = sizeof (M3CodePageHeader) + sizeof (code_t) * i_minNumLines;
 
+    // check addition overflow
+    if (pageSize < sizeof (M3CodePageHeader)) {
+        return NULL;
+    }
+
     pageSize = (pageSize + (d_m3CodePageAlignSize-1)) & ~(d_m3CodePageAlignSize-1); // align
+    // check alignment overflow
+    if (pageSize == 0) {
+        return NULL;
+    }
+
     page = (IM3CodePage)m3_Malloc ("M3CodePage", pageSize);
 
     if (page)
diff --git a/source/m3_compile.c b/source/m3_compile.c
@@ -322,11 +322,8 @@ u16  GetExtraSlotForStackIndex  (IM3Compilation o, u16 i_stackIndex)
 static inline
 void  TouchSlot  (IM3Compilation o, u16 i_slot)
 {
-    if (o->function)
-    {
-        // op_Entry uses this value to track and detect stack overflow
-        o->maxStackSlots = M3_MAX (o->maxStackSlots, i_slot + 1);
-    }
+    // op_Entry uses this value to track and detect stack overflow
+    o->maxStackSlots = M3_MAX (o->maxStackSlots, i_slot + 1);
 }
 
 static inline
@@ -1900,6 +1897,7 @@ _   (CompileBlock (o, blockType, i_opcode));
 static
 M3Result  CompileElseBlock  (IM3Compilation o, pc_t * o_startPC, IM3FuncType i_blockType)
 {
+    IM3CodePage savedPage = o->page;
 _try {
 
     IM3CodePage elsePage;
@@ -1907,19 +1905,17 @@ _   (AcquireCompilationCodePage (o, & elsePage));
 
     * o_startPC = GetPagePC (elsePage);
 
-    IM3CodePage savedPage = o->page;
     o->page = elsePage;
 
 _   (CompileBlock (o, i_blockType, c_waOp_else));
 
 _   (EmitOp (o, op_Branch));
     EmitPointer (o, GetPagePC (savedPage));
-
-    ReleaseCompilationCodePage (o);
-
-    o->page = savedPage;
-
 } _catch:
+    if(o->page != savedPage) {
+        ReleaseCompilationCodePage (o);
+    }
+    o->page = savedPage;
     return result;
 }
 
@@ -2702,7 +2698,13 @@ _try {
 _           (PopType (o, type));
         }
     }
-    else o->stackIndex -= numParams;
+    else {
+        if (IsStackPolymorphic (o) && o->block.blockStackIndex + numParams > o->stackIndex) {
+            o->stackIndex = o->block.blockStackIndex;
+        } else {
+            o->stackIndex -= numParams;
+        }
+    }
 
     u16 paramIndex = o->stackIndex;
     block->exitStackIndex = paramIndex; // consume the params at block exit
@@ -2730,7 +2732,7 @@ _           (PopType (o, type));
         u16 slot = GetSlotForStackIndex (o, paramIndex + i);
         Push (o, type, slot);
 
-        if (slot >= o->slotFirstDynamicIndex)
+        if (slot >= o->slotFirstDynamicIndex && slot != c_slotUnused)
             MarkSlotsAllocatedByType (o, slot, type);
     }
 
```

### Sites recorded by the pipeline (unlabelled)

1. source/m3_code.c:27 (NewCodePage)
