// old
/*
const pcap = require('pcap2')
const tcpTracker = new pcap.TCPTracker()
function openPcap(opts) {
    const { ports, filter } = opts
    console.log(`pcap filter: ${filter}`)
    const pcapSession = new pcap.Session('en0', { filter })

    tcpTracker.on('session', session => {
        const { dst_name, src_name } = session
        console.log(`Begin TCP session ${src_name}->${dst_name}`)

        session.on('data recv', onTcpPacket.bind({ ports }))

        session.on('end', session => {
            console.log('End TCP session')
        })
    })

    pcapSession.on('packet', raw => {
        const packet = pcap.decode.packet(raw)
        tcpTracker.track_packet(packet)
    })
}
*/

const { Cap, decoders } = require('cap')
const { PROTOCOL } = decoders
const { getFfxivProcessInfo } = require('./lib/process')
const { onTcpPacket } = require('./lib/packet')

function openPcap(opts) {
    const { ip, ports, filter } = opts
    const pcap = new Cap()
    const device = Cap.findDevice(ip) // TODO: will fail on macOS
    const bufsiz = 10*1024*1024
    const buffer = new Buffer(Math.pow(2, 16)-1)
    const linkType = pcap.open(device, filter, bufsiz, buffer)
    pcap.on('packet', (nbytes, trunc) => {
        if (linkType !== 'ETHERNET') return

        const ether = decoders.Ethernet(buffer)
        if (ether.info.type !== PROTOCOL.ETHERNET.IPV4) return // needed?

        // Well, it has to be TCP at this point. The filter says so.
        const len = ether.info.totallen - ether.hdrlen
        t = decoders.TCP(buffer, ether.offset)
        console.log(t.info)
    })
}

getFfxivProcessInfo()
.then(res => {
    console.log(res)
    openPcap(res)
})
.catch(err => {
    console.error(err)
})
