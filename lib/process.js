const { exec } = require('child_process')

function getPid(program) {
    switch (process.platform) {
    case 'darwin':
        return new Promise((resolve, reject) => {
            exec(`ps -A | grep \'${program}\'`, (err, stdout, stderr) => {
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
    case 'win32':
        return new Promise((resolve, reject) => {
            const tasklist = require('tasklist')
            tasklist()
            .then(tasks => {
                const progRe = new RegExp(program, 'i')
                const task = tasks.find(t => progRe.test(t.imageName))
                if (task && task.pid) {
                    resolve(task.pid)
                } else {
                    reject(new Error('Process not found!'))
                }
            })
            .catch(err => reject(err))
        })
    default:
        return Promise.reject(new Error(`Unsupported platform: ${process.platform}`))
    }
}

function parsePorts(stdoutLines) {
    let portsRe
    switch (process.platform) {
    case 'win32':
        portsRe = /TCP\s+(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(?:\d+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d+)/
        break
    case 'darwin':
    default:
        portsRe = /TCP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d+)\-\>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d+)/
    }
    let ports = []
    stdoutLines.forEach(line => {
        const portsMatch = line.match(portsRe)
        if (!portsMatch) return
        ports.push(portsMatch[2])
    })
    return ports
}

function buildFilterString(ports) {
    let pcapFilter = `ip proto \\tcp and (`
    ports.forEach((port, i) => {
        if (i !== 0) pcapFilter += ' or '
        pcapFilter += `port ${port}`
    })
    pcapFilter += ')'
    return pcapFilter
}

function getPcapFilterFromPid(pid) {
    switch (process.platform) {
    case 'darwin':
        return new Promise((resolve, reject) => {
            exec(`lsof -p ${pid} | grep TCP`, (err, stdout, stderr) => {
                if (err) return reject(err)
                if (stderr) return reject(stderr)

                const lines = stdout.split('\n')
                const ports = parsePorts(lines)
                const pcapFilter = buildFilterString(ports)
                resolve({
                    ports: ports,
                    filter: pcapFilter
                })
            })
        })
    case 'win32':
        return new Promise((resolve, reject) => {
            exec(`netstat -ano`, (err, stdout, stderr) => {
                if (err) return reject(err)
                if (stderr) return reject(stderr)

                const pidRe = new RegExp(`${pid}\r$`)
                const lines = stdout.split('\n')
                    .filter(line => pidRe.test(line))
                const ports = parsePorts(lines)
                const pcapFilter = buildFilterString(ports)
                resolve({
                    ports: ports,
                    filter: pcapFilter
                })
            })
        })
    default:
        return Promise.reject(new Error(`Unsupported platform: ${process.platform}`))
    }
}

function getFfxivPcapFilter() {
    return getPid('ffxiv')
    .then(res => {
        const pid = res
        console.log(`FFXIV running as PID ${pid}`)
        return getPcapFilterFromPid(pid)
    })
}

module.exports = {
    getFfxivPcapFilter
}
