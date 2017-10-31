const zlib = require('zlib')
const {
    pktSuper,
    pktGroup,
    pktAtom,
    pktTargetSkill,
    pktEffect
} = require('./parsers')

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

function logpkt(pkt) {
    console.log(`0x${pkt.opcode.toString(16)}`)
    console.log(pkt.data.toString('hex'))
    console.log('---\n')
}

function handleEffect(fx) {
    switch (fx.id) {
    case 3:
        console.log(`Regular hit: ${fx.value} damage`)
        break
    case 259:
        console.log(`Critical hit: ${fx.value} damage`)
        break
    case 515:
        console.log(`Direct hit: ${fx.value} damage`)
        break
    default:
        console.log(fx)
    }
}

function handleTargetSkill(pkt) {
    const skill = pktTargetSkill.parse(pkt.data)
    console.log(skill)
    // TODO: clean this up
    let effects = []
    for (let i=0; i<8; i++) {
        const off = i*8
        const fx = pktEffect.parse(skill.effects.slice(off, off+8))
        effects.push(fx)
    }
    effects.forEach(handleEffect)
}

function handleSubPacket(sub) {
    const pkt = pktAtom.parse(sub.data)
    switch (pkt.opcode) {
    case 0xf0:
        // console.log('fc class info')
        break
    case 0xee:
        // console.log('fc info')
        break
    case 0xf6:
        // console.log('fc message info')
        break
    case 0xfb:
        // single skill
        handleTargetSkill(pkt)
        break
    case 0xf4:
        // console.log('aoe skill')
        break
    case 0xbe:
        // console.log('linkshell info')
        break
    case 0x64:
        // console.log('tell')
        break
    case 0x65:
        // some sort of heartbeat
        break
    case 0x1e4:
        // console.log('private estate info')
        break
    case 0x11c:
        // console.log('player spawn info')
        break
    case 0x11d:
        // console.log('possibly related to player spawn info')
        break
    case 0x143:
    case 0x145:
        // console.log('current target info (??)')
        // console.log(packet.data.toString('utf8'))
        break
    case 0x126:
        // Targeting info. Triggered when clicking on a PC/NPC.
        break
    case 0x127:
        // battle related
        // triggered by skills and auto-attacks
        break
    case 0x128:
        // battle related
        // only triggered when using ranged abilities
        // console.log(packet.data)
        break
    case 0x65:
    case 0x1025:
        // heartbeat-ish stuff
        // console.log('Ignoring heartbeat')
        break
    default:
        // console.log('unhandled opcode:', packet.opcode.toString(16))
        // console.log(packet.data.toString('utf8'))
    }
}

function onTcpPacket(data) {
    let processed = 0
    // TODO: Handle TCP packets that are split up
    // Probably need to bring back in the PacketParser class.
    while (processed < data.length) {
        let sup
        try {
            sup = pktSuper.parse(Buffer.from(data, processed))
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
        let sub = pktGroup.parse(sup.data)
        subPackets.push(sub)
        let subLength = sup.data.length - sub.length
        while (subLength > 0) {
            sub = pktGroup.parse(sub.nextPacket)
            subPackets.push(sub)
            subLength -= sub.length
        }

        // console.log('Subpackets:')
        subPackets.forEach(s => {
            // console.log(`[s]Buffer:${s.data.toString('hex')}`)
            // console.log(`[s]Text:${s.data.toString('utf8')}`)
            // console.log(s)
            handleSubPacket(s)
        })
    }
}

module.exports = {
    onTcpPacket
}
