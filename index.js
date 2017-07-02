// get ports
const { exec } = require('child_process')

function getFfxivPid() {
    return new Promise((resolve, reject) => {
        exec('ps -A | grep \'ffxiv.exe\'', (err, stdout, stderr) => {
            if (err) return reject(err)
            if (stderr) return reject(stderr)

            // TODO: error prone
            const [pidMatch] = stdout.match(/^(\d+)\s/)
            if ([pidMatch]) {
                resolve([pidMatch][0])
            } else {
                reject(new Error('Process not found!'))
            }
        })
    })
}

function getPcapFilterFromPid(pid) {
    return new Promise((resolve, reject) => {
        exec(`lsof -p ${pid} | grep TCP`, (err, stdout, stderr) => {
            if (err) return reject(err)
            if (stderr) return reject(stderr)

            const lines = stdout.split('\n')
            const portsRe = /TCP\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:(\d+)\-\>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:(\d+)/
            let ports = []
            lines.forEach(line => {
                const portsMatch = line.match(portsRe)
                if (!portsMatch) return
                ports.push(portsMatch[1])
                // portsMatch[2] is dest/server port if we ever need it
            })
            let pcapFilter = ''
            ports.forEach((port, i) => {
                if (i !== 0) pcapFilter += ' and '
                pcapFilter += `tcp port ${port}`
            })
            resolve(pcapFilter)
        })
    })
}

// pcap
const pcap = require('pcap2')
const tcpTracker = new pcap.TCPTracker()
const Parser = require('binary-parser').Parser

const ffxivPacket = new Parser()
    .uint16le('type') // 0:1
    .skip(23)
    .uint32le('length') // 24:27
    .skip(3)
    .uint16le('blocklen') // 30:31
    .skip(2)
    .uint8('zlib') // 33
    .skip(6)
    .uint16le('typemod') // 39:40
    .buffer('data', {
        length: function () {
            return this.length
        }
    })

function hexise(pkt) {
    const hexed = Object.assign({}, pkt)
    Object.keys(hexed).forEach(key => {
        const val = hexed[key]
        if (typeof val === 'number') {
            hexed[key] = `0x${val.toString(16)}`
        }
    })
    return hexed
}

getFfxivPid()
.then(res => {
    const pid = res
    console.log(`FFXIV running as PID ${pid}`)
    return getPcapFilterFromPid(pid)
})
.then(res => {
    // const filter = res
    // const filter = 'ip proto \\tcp and dst host 192.168.1.1 and (dst port 59186 or dst port 59187)'
    const filter = 'ip proto \\tcp and host 124.150.157.27 and (port 54992 or port 59186 or port 59187)'
    // TODO: Use the above filter format, figure out which direction we need and fix filter generator
    console.log(`pcap filter: ${filter}`)
    const pcapSession = new pcap.Session('en0', { filter })

    tcpTracker.on('session', session => {
        const { dst_name, src_name } = session
        console.log(`Begin TCP session ${dst_name}->${src_name}`)

        session.on('data recv', (session, data) => {
            const { dst_name, src_name } = session
            console.log(`${dst_name}->${src_name}`)
            console.log(`Buffer:${data.toString('hex')}`)
            console.log(`Text:${data}`)
            console.log(hexise(ffxivPacket.parse(data)))
            console.log('\n')
        })

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
