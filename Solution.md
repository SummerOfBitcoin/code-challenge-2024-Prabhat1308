## Design Approach

For the block building first the process was to validate the transactions. After the valid transactions were ready I had to mine them efficiently . For this the algorithm I thought was greedy O/1 knapsack using heap . Heaps provide good efficiency with the fact that I used max heap which store the value with best fee/weight ratio. 

## Implementation details

### Steps
1. extract data from json to vec<u8> in rust using serde
2. implement structs according to how its stored in json 
3. verification of utxos
4. verifications of valid fees
5. verification of signatures (segwit , non-segwit and wrapped-segwits)
6. extract valid transactions and create TxNodes with the data of txid , fee , weight 
7. create a heap and store the TxNodes which dont have parent transactions
8. Take the first element from heap and then add the children transactions of that transaction in the heap
9. repeat the process till max weight is reached (space for coinbase left only)
10. create merkle root
11. create witness root hash
12. create blockheader
13. create coinbase transaction
14. write the data in the output.txt 

## Results and Performance 

fees extracted - 19808182
max fees - 20616923
block size - 3995700
max blocksize - 4000000 

Using algorithm used 96.077 % fees was extracted and 99.89 % of block space was used which is an excellent result compared without unnecessary complications and good enough time of 6 mins (may vary for different languages and machine capacity)

## Conclusion 

For now the issue is there are not much information about a specific parts of the assignment which thankfully were later removed to ease out the assignment such as 
1. there is no clear article / resource explaining how p2tr trnsactions are formed and validated expect the bitcoin-core source code which I feel is not enough. It was not even in the dev docs.
2. Also I was unable to find a resource explaining the verification of p2sh tx verification clearly.

This may not be a problem for seasoned devs but hinders the new contributers from starting out. Efforts should be made to make a resource compiling all the necessary dev informations with live code examples in various languages . 

### Resources
mempool.space site
bitcoin dev techinal documentation
learnmeabitcoin site 
bitcoin-cli
Bitcoin stack exchange
BIP 143 / BIP 141

