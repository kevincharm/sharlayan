From: https://ffxiv-app.com/topic/31/network-packet-structures/12

Zacharot Nov 21, 2015, 1:44 PM 
@agoln There is no encryption anywhere on the incoming. I have a 100% parse rate to get the inner messages.

My terminology sometimes isn't the clearest, but I'm uncertain of exactly what these things are called in an information system like this.

```
Packet (frame header + chat messages | zlib(blocks)))

Packet------Packet--------Packet---Packet---Packet-----------------------------------Pac..
Frame--------------------------------------------Frame-----Frame-------------------------------Fra..
Frame(Zlib(blocks,blocks,blocks))Frame(b)Frame(Z(b,b,b,b,b,b,b,b,b))Fra..
```

Since 3.0 a lot seems to have been rearranged. There is more consistency in what is encoded and what isn't. Amusingly only the tells seem to not be zlib compressed, though I can't figure out why.

Byte offsets are 0 indexed. Feel free to convert my notes if you are simply counting as I so often do.

On the frame, headers seem to be 40 bytes. The only bytes I actively make use of are 0:1, 24:27, 30:31, 33 and 40:41. 0:2 and 40:41 are my "type" bytes. 24:27 are the frame length. Types are 0:1==5252 and 0:1==0000 && 40:41 == 789C || 1800
I haven't found useful data in anything else so I just filter and use these.

Once you have a complete frame:
A frame can contain multiple blocks - they usually do. Number of expected blocks is 30:31. If the blocks are compressed, that's stored in 33.
If the blocks are compressed, strip the first 40 bytes and the rest is a zlib encoded set of blocks.
If it's not compressed, strip the first 40 bytes and the rest is a set of blocks.

From here it's simple. Blocks are stacked, the length bytes are just the first 4 bytes of each block.

In rare cases, I've found that a block can span frames, I don't know why this happens, but it's a very rare thing. If you have a short block, hang onto it and check the next frame's first block to see if the two go together.

There are other exceptions, such as I've found frames inside of frames. I have a check for this in my code. I've found zlib'd frames inside of zlib'd frames instead of blocks. As noted above I've found truncated blocks. I've found blocks that contain more blocks!

Once you have the string of blocks, which are likely just structs, you are off to the races. I recommend writing something to compare like structs to look for changes, it was the fastest way I found to decode them.

Nearly every block appears to have a 32 byte header, I haven't figured out those nuances between them all yet, or what they represent, such as why some patterns are repeated over and over.

Some blocks/structs inform ones to follow. An example is the history block for the market board.

Byte 14 and Byte 15 I call b1 and b2 - these are my keys to block type, history count is b1==04 && b2 == 01
I'll use 32+N to signify that the header is 32 bytes, but 32+28 would be the 61st byte, not the 29th. My code is set up to strip the header, but I want to clarify the exact position and don't feel like converting all the bytes and making a mistake in translation.

byte 32+28:31 = item_id
byte 32+38:39 = number of items for sale rows (not history)

You need these, because the items data block doesn't specify number of expected rows.

history data block is b1==09 && b2==01
32+0:3 = item_id
every 52 bytes is a history row so 32+:51, 32+52:103, etc
i=integer (4 bytes)
b=byte (1 byte)
s=string (N bytes)
row structure is IIIIBBs(34)
item_id, price, date(unix), quantity, is_hq, has_materia, buyer_name

Item rows: b1 == 5 && b2 == 1
Header I believe is 28 bytes, there may be useful info in there, but I just iterate the data itself.

L=4
H=2
B=1
Row is 112 bytes
LBBBBLHHLHHLHHLLLLLHBBBBBBHHHHBBBBBBBBs32BBBB

u = unknown
auction_id,u,u,u,u,retainer id,user1,u,user_id,user2,u,crafted by,user3,u,price,fee,quant,item_id,post_date(unix),is_item,u,u,u,u,u,u,materia1,materia2,materia3,materia4,u,u,u,u,u,u,u,u,retainer name, is_hq, has_materia, city,u

I may have messed up those offsets, but I believe you have enough info either way.

That should speed you on your way.
