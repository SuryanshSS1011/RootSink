# Chain-label annotation: instructions for raters

Thank you for rating. This audit checks the labels of a C/C++ vulnerability dataset against
independent expert judgement. Your answers are compared with the dataset's labels and with the
other rater's answers. You are not being tested; the dataset is.

## What is in this folder

1. `practice/packet.html` and `practice/sheet.csv`: 6 practice items. Do these first, then send
   the practice sheet back. You will get an answer key for them, so you can calibrate on the
   conventions before the real items. Practice answers are never scored.
2. `packet.html`: the 150 real items, with the codebook at the top. `packet.md` is the same text
   as plain Markdown.
3. `sheet.csv`: one row per item (`item-1` to `item-150`). Fill this in and return it.

## How to work

1. Read the codebook at the top of the packet once, carefully. It defines the six columns, the
   site roles, and three conventions the dataset follows (use-after-free, uninitialised memory,
   NULL dereference).
2. Do the practice items and compare with the answer key.
3. Rate the 150 items in order. Expect about 4-5 minutes per item once you are used to the
   format, roughly 10-12 hours in total. Several sittings are fine.
4. Keep the sheet's column names and item ids unchanged. Leave no cell empty: use `unclear`
   when you cannot decide. The `note` column is optional.

## Please do not

1. Look an item up (the project's bug tracker, the commit, OSS-Fuzz, CVE entries).
2. Discuss items with the other rater before both sheets are returned.
3. Use an AI tool on the items.

## Returning your sheet

Send `sheet.csv` back, renamed `sheet_<your initials>.csv`, with a short note giving your years
of C/C++ security experience, your familiarity with sanitizer reports and CWE, and your
affiliation type (academia or industry). The paper reports these, without names unless you agree.
