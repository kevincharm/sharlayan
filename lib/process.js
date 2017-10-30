const { exec } = require('child_process')

function getFfxivPid() {
    return new Promise((resolve, reject) => {
        exec('ps -A | grep \'ffxiv.exe\'', (err, stdout, stderr) => {
            if (err) return reject(err)
            if (stderr) return reject(stderr)

            const [pidMatch] = stdout.match(/^(\d+)\s/) || []
            if (pidMatch) {
                resolve(pidMatch)
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
            const portsRe = /TCP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d+)\-\>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d+)/
            let ports = []
            lines.forEach(line => {
                const portsMatch = line.match(portsRe)
                if (!portsMatch) return
                ports.push(portsMatch[2])
                // portsMatch[2] is dest/server port if we ever need it
            })
            let pcapFilter = `ip proto \\tcp and (`
            ports.forEach((port, i) => {
                if (i !== 0) pcapFilter += ' or '
                pcapFilter += `port ${port}`
            })
            pcapFilter += ')'
            resolve({
                ports: ports,
                filter: pcapFilter
            })
        })
    })
}

module.exports = {
    getFfxivPid,
    getPcapFilterFromPid
}
