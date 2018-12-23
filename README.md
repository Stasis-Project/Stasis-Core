
Stasis development tree

Stasis is a PoS-based cryptocurrency.

SAS is dependent upon libsecp256k1 by sipa, the sources for which can be found here:
https://github.com/bitcoin/secp256k1

POS Reward: 55 SAS
Block Spacing: 60 Seconds
Diff Retarget: 10 Blocks
Maturity: 20 Blocks
Stake Minimum Age: 2 Hours

40 MegaByte Maximum Block Size (40X Bitcoin Core)


Mainnet
Default Port = 33322
RPC Port = 33344

Testnet
Default Port = 11133
RPC Port = 11166

Magic Bytes: 0x31 0x33 0x33 0x37

SAS includes an Address Index feature, based on the address index API (searchrawtransactions RPC command) implemented in Bitcoin Core but modified implementation to work with the SAS codebase (PoS coins maintain a txindex by default for instance).

Initialize the Address Index By Running with -reindexaddr Command Line Argument.  It may take 10-15 minutes to build the initial index.

Stasis has an estimated transaction volume of 12,000 TPS.

Bandwidth Requirements:
Down: 	22.37Mbps
Up: 	156.587Mbps

Disk Requirements:
Data Cap : 14TB/month
Disk Capacity : 21.1TB per year

