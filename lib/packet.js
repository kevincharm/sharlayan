const Parser = require('binary-parser').Parser
const zlib = require('zlib')

const superPacket = new Parser()
    .uint16le('type') // 0:1, end at 2
    .skip(14)
    .uint32le('timestampLsb')
    .uint32le('timestampMsb')
    .uint32le('length') // 24:27, end at 28
    .skip(2) // 28+2 = 30
    .uint16le('subpackets') // 30:31, end at 32
    .skip(1) // wtf is this byte
    .uint8('zlib') // 33
    .skip(4) // 34+5
    .uint16le('typemod') // 39:40
    .buffer('data', {
        length: function () {
            return this.length-40
        }
    })

const subPacket = new Parser()
    .uint32le('length') // 0:4
    .uint32le('u64_1_lsb') // 5:8, idk
    .uint32le('u64_1_msb') // 9:12, idk
    .uint16le('type')
    .uint16le('type2')
    .buffer('data', {
        length: function () {
            return this.length-4-10-2
        }
    })
    .buffer('nextPacket', {
        readUntil: 'eof'
    })

const packet = new Parser()
    .skip(2)
    .uint16le('opcode')
    .skip(2)
    .uint16le('timestamp')
    .buffer('data', { readUntil: 'eof' })

function unzlib(buf) {
    try {
        const unzipped = zlib.unzipSync(buf)
        // console.log('\x1B[32;1mSuccessful unzip.\x1B[0m')
        return unzipped
    } catch (err) {
        console.log('\x1B[31;1mFailed to unzip!\x1B[0m')
        return buf
    }
}

function handleSubPacket(packet) {
    console.log(`0x${packet.opcode.toString(16)}`)
    switch (packet.opcode) {
    case 0xf0:
        console.log('fc class info')
        break
    case 0xee:
        console.log('fc info')
        break
    case 0xf6:
        console.log('fc message info')
        break
    case 0xf1:
        console.log('single skill')
        break
    case 0xf4:
        console.log('aoe skill')
        break
    case 0xbe:
        console.log('linkshell info')
        break
    case 0x64:
        console.log('tell')
        break
    case 0x1e4:
        console.log('private estate info')
        break
    case 0x11c:
        console.log('player spawn info')
        break
    case 0x11d:
        console.log('possibly related to player spawn info')
        break
    case 0x126:
        console.log('targeting info')
        break
    case 0x145:
        console.log('current target info (??)')
        break
    case 0x127:
        console.log('battle related?')
        break
    case 0x128:
        console.log('a very uniform packet structure')
        break
    case 0x65:
    case 0x143:
    case 0x1025:
        // heartbeat-ish stuff
        console.log('Ignoring heartbeat')
        break
    default:
        console.log('unhandled opcode:', packet.opcode.toString(16))
        console.log(packet.data.toString('utf8'))
    }
    console.log('---\n')
}

function onTcpPacket(data) {
    let processed = 0
    // TODO: Handle TCP packets that are split up
    // Probably need to bring back in the PacketParser class.
    while (processed < data.length) {
        let sup
        try {
            sup = superPacket.parse(Buffer.from(data, processed))
        } catch (err) {
            console.log('\x1B[31;1mParser assert.\x1B[0m')
            break
        }
        processed += sup.length

        // parse each embedded subpacket
        if (sup.zlib) {
            sup.data = unzlib(sup.data)
        }

        const subPackets = []
        let sub = subPacket.parse(sup.data)
        subPackets.push(prettify(sub))
        let subLength = sup.data.length - sub.length
        while (subLength > 0) {
            sub = subPacket.parse(sub.nextPacket)
            subPackets.push(prettify(sub))
            subLength -= sub.length
        }

        // console.log('Subpackets:')
        subPackets.forEach(s => {
            // console.log(`[s]Buffer:${s.data.toString('hex')}`)
            // console.log(`[s]Text:${s.data.toString('utf8')}`)
            console.log(s.type, s.type2)
            handleSubPacket(packet.parse(s.data))
        })
    }
}

module.exports = {
    onTcpPacket
}
