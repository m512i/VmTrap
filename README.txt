Injects a custom __vtrap stub into a PE’s VM handler table, decrypts/dispatches handlers via your C callback.

Build and link as DLL, then run:
  myhooker.exe --bin <dll> --table <RVA> --base <base>

Woohoo!! just read the code.
