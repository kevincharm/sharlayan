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

const cap = require('cap')
const { getFfxivPcapFilter } = require('./lib/process')
const { onTcpPacket } = require('./lib/packet')

getFfxivPcapFilter()
.then(res => {
    console.log(res)
})
.catch(err => {
    console.error(err)
})
