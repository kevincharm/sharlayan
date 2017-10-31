const Parser = require('binary-parser').Parser

const pktSuper = new Parser()
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

const pktGroup = new Parser()
    .uint32le('length') // 0:4
    .uint32le('actor') // 5:8, idk
    .uint32le('target') // 9:12, idk
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

const pktAtom = new Parser()
    .skip(2)
    .uint16le('opcode')
    .skip(2)
    .uint16le('timestamp')
    .skip(8)
    .buffer('data', { readUntil: 'eof' })

const pktTargetSkill = new Parser()
    .skip(8)
    .uint16le('id')
    .skip(30)
    .buffer('effects', { length: 64 })
    .skip(2)
    .uint32le('target')

const pktEffect = new Parser()
    .uint16le('id')
    .uint16le('id2')
    .uint32le('value')

module.exports = {
    pktSuper,
    pktGroup,
    pktAtom,
    pktTargetSkill,
    pktEffect
}
