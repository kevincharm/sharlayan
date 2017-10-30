const pcap = require('pcap2')
const tcpTracker = new pcap.TCPTracker()
const {
    getFfxivPid,
    getPcapFilterFromPid
} = require('./lib/process')
const { onTcpPacket } = require('./lib/packet')

getFfxivPid()
.then(res => {
    const pid = res
    console.log(`FFXIV running as PID ${pid}`)
    return getPcapFilterFromPid(pid)
})
.then(res => {
    const { ports, filter } = res
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
})
.catch(err => {
    console.error(err)
})
