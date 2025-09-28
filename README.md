## OAB Files

EXPORT Outlook offline address book all contacts also Global Address List
1. First, make sure Outlook offline address book is updated. Go to send/receive tab and click on "Download Address Book"
check Download changes since last Send/Receive and select /offline Global Address List.
2. Go to C:\Users\%username%\AppData\Local\Microsoft\Outlook
3. Get udetails.oab file
4. Use OAB_decipher.py that program creates JSON file with records of contacts
5. You can directly create vcf (vCard) with convert_into_vCard.py script
6. You can import vcf file into your email client (e.g. Thunderbird, etc.)

That project was created thanks to [antimatter15](https://github.com/antimatter15/boa) and [byteDJINN](https://github.com/byteDJINN/BOA)