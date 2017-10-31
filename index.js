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

        const ipv4 = decoders.IPV4(buffer, ether.offset)
        if (ipv4.info.protocol !== PROTOCOL.IP.TCP) return

        const tcp = decoders.TCP(buffer, ipv4.offset)
        const tcpLen = ipv4.info.totallen - ipv4.hdrlen - tcp.hdrlen
        const packet = buffer.slice(tcp.offset, tcp.offset + tcpLen)

        if (ports.find(p => p === tcp.info.srcport.toString())) {
            console.log('incoming')
            console.log(ipv4.info, tcp.info)
            console.log('---')
            onTcpPacket(packet)
        } else if (ports.find(p => p === tcp.info.dstport.toString())) {
            console.log('outgoing')
            console.log(ipv4.info, tcp.info)
            console.log('---')
        }
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
