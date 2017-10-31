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

// For subPackets
const packetTypes = {
    0x0: 'Position/control (from server)',
    0x1ac: 'Position/control (from client)',
    0x355: 'Frontlines player message',
    0x354: 'Frontlines summary message',
    0x2df: 'Wolves\' Den player+summary message',
    0x2de: 'Duty finder message',
    0x85bf: 'Zone data?',
    0x3fa3: 'Damage info?',
    0x3f9d: 'Mount related???',
    0x3b34: 'Mount related???'
}

const subPacket = new Parser()
    .uint32le('length')
    .uint32le('u64_1_lsb') // don't know
    .uint32le('u64_1_msb') // don't know
    .uint16le('u16_1') // don't know
    .uint16le('type') // seems to be some message type
    .buffer('data', {
        length: function () {
            return this.length-4-10-2
        }
    })
    .buffer('nextPacket', {
        readUntil: 'eof'
    })

function prettify(pkt) {
    const hexed = Object.assign({}, pkt)
    Object.keys(hexed).forEach(key => {
        const val = hexed[key]

        if (typeof val === 'number')
            hexed[key] = `0x${val.toString(16)}`

        const packetType = packetTypes[val]
        if (key === 'type' && !!packetType)
            hexed[key] = `${packetType} (${hexed[key]})`
    })
    if (hexed.timestampLsb && hexed.timestampMsb) {
        // TODO: Handle uint64 timestamps
    }
    return hexed
}

function unzlib(buf) {
    try {
        const unzipped = zlib.unzipSync(buf)
        console.log('\x1B[32;1mSuccessful unzip.\x1B[0m')
        return unzipped
    } catch (err) {
        console.log('\x1B[31;1mFailed to unzip!\x1B[0m')
        return buf
    }
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

        console.log('Subpackets:')
        subPackets.forEach(s => {
            console.log(`[s]Buffer:${s.data.toString('hex')}`)
            console.log(`[s]Text:${s.data.toString('utf8')}`)
            console.log(s)
        })
        console.log('---\n')
    }
}

module.exports = {
    onTcpPacket
}
