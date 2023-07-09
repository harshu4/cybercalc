//Initital data with all the devices and vulnerabilites

device_vulnerabilities = {
    'Humidity Sensor': [
        {
            'Vulnerability ID': 'CVE-2022-30339',
            'Exploitability Score': 0.8,
            'Impact Score': 3.6,
            'CVSS Score': 4.4
        },
        {
            'Vulnerability ID': 'CVE-2022-46313',
            'Exploitability Score': 3.9,
            'Impact Score': 1.4,
            'CVSS Score': 5.3
        }
    ],
    'Ventilator': [
        {
            'Vulnerability ID': 'CVE-2022-42756',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ],
    'CO2 Sensor': [
        {
            'Vulnerability ID': 'CVE-2022-39106',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ],
    'Heater': [
        {
            'Vulnerability ID': 'CVE-2022-3575',
            'Exploitability Score': 3.9,
            'Impact Score': 5.9,
            'CVSS Score': 9.8
        },
        {
            'Vulnerability ID': 'CVE-2022-39128',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        },
        {
            'Vulnerability ID': 'CVE-2022-39127',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ],
    'Window Sensor': [
        {
            'Vulnerability ID': 'CVE-2022-39122',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ],
    'Air Conditioner': [
        {
            'Vulnerability ID': 'CVE-2022-39121',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        },
        {
            'Vulnerability ID': 'CVE-2022-39105',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ],
    'CO Detection Sensor': [
        {
            'Vulnerability ID': 'CVE-2022-26474',
            'Exploitability Score': 0.8,
            'Impact Score': 5.9,
            'CVSS Score': 6.7
        }
    ],
    'Occupancy Sensor': [
        {
            'Vulnerability ID': 'CVE-2022-2841',
            'Exploitability Score': 1.2,
            'Impact Score': 1.4,
            'CVSS Score': 2.7
        }
    ],
    'Fire Alarm': [
        {
            'Vulnerability ID': 'CVE-2022-39128',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        },
        {
            'Vulnerability ID': 'CVE-2022-39127',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ],
    'Brightness Sensor': [
        {
            'Vulnerability ID': 'CVE-2022-37063',
            'Exploitability Score': 2.3,
            'Impact Score': 2.7,
            'CVSS Score': 5.4
        }
    ],
    'Motion Sensor': [
        {
            'Vulnerability ID': 'CVE-2022-37062',
            'Exploitability Score': 3.9,
            'Impact Score': 3.6,
            'CVSS Score': 7.5
        }
    ],
    'Smoke Sensor': [
        {
            'Vulnerability ID': 'CVE-2022-37061',
            'Exploitability Score': 3.9,
            'Impact Score': 5.9,
            'CVSS Score': 9.8
        }
    ],
    'Media Player': [
        {
            'Vulnerability ID': 'CVE-2022-26474',
            'Exploitability Score': 0.8,
            'Impact Score': 5.9,
            'CVSS Score': 6.7
        },
        {
            'Vulnerability ID': 'CVE-2022-39127',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ],
    'Screen Projector': [
        {
            'Vulnerability ID': 'CVE-2022-3575',
            'Exploitability Score': 3.9,
            'Impact Score': 5.9,
            'CVSS Score': 6.7
        },
        {
            'Vulnerability ID': 'CVE-2022-39128',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ],
    'Smart TV': [
        {
            'Vulnerability ID': 'CVE-2022-37063',
            'Exploitability Score': 2.3,
            'Impact Score': 2.7,
            'CVSS Score': 5.4
        }
    ],
    'Speaker': [
        {
            'Vulnerability ID': 'CVE-2022-37062',
            'Exploitability Score': 3.9,
            'Impact Score': 3.6,
            'CVSS Score': 7.5
        },
        {
            'Vulnerability ID': 'CVE-2022-39122',
            'Exploitability Score': 1.8,
            'Impact Score': 3.6,
            'CVSS Score': 5.5
        }
    ]
}

// individual device/node assesment (derived data)

let devicevuln = {
    'Humidity Sensor': {
        asp: 0.43879999999999997,
        sr: 0.5459999999999999,
        ai: 3.6,
        cvss: 5.3
    },
    'Ventilator': { asp: 0.17999999999999994, sr: 0.648, ai: 3.6, cvss: 5.5 },
    'CO2 Sensor': { asp: 0.17999999999999994, sr: 0.648, ai: 3.6, cvss: 5.5 },
    'Heater': { asp: 0.589836, sr: 2.301, ai: 5.9, cvss: 9.8 },
    'Window Sensor': { asp: 0.17999999999999994, sr: 0.648, ai: 3.6, cvss: 5.5 },
    'Air Conditioner': { asp: 0.3275999999999999, sr: 0.648, ai: 3.6, cvss: 5.5 },
    'CO Detection Sensor': {
        asp: 0.07999999999999996,
        sr: 0.47200000000000003,
        ai: 5.9,
        cvss: 6.7
    },
    'Occupancy Sensor': { asp: 0.12, sr: 0.16799999999999998, ai: 1.4, cvss: 2.7 },
    'Fire Alarm': { asp: 0.3275999999999999, sr: 0.648, ai: 3.6, cvss: 5.5 },
    'Brightness Sensor': { asp: 0.22999999999999998, sr: 0.621, ai: 2.7, cvss: 5.4 },
    'Motion Sensor': { asp: 0.39, sr: 1.4040000000000001, ai: 3.6, cvss: 7.5 },
    'Smoke Sensor': { asp: 0.39, sr: 2.301, ai: 5.9, cvss: 9.8 },
    'Media Player': { asp: 0.24559999999999993, sr: 0.648, ai: 5.9, cvss: 6.7 },
    'Screen Projector': { asp: 0.4998, sr: 2.301, ai: 5.9, cvss: 6.7 },
    'Smart TV': { asp: 0.22999999999999998, sr: 0.621, ai: 2.7, cvss: 5.4 },
    'Speaker': { asp: 0.4998, sr: 1.4040000000000001, ai: 3.6, cvss: 7.5 }
}




// connecting node data for path (derived)


let devicelist = {

    "Humidity Sensor": ["Ventilator", "Air Conditioner", "Heater"],
    "Ventilator": [],
    "CO2 Sensor": ["Ventilator"],
    "Heater": [],
    "Window Sensor": ["Heater", "Air Conditioner"],
    "Air Conditioner": [],
    "CO Detection Sensor": ["Fire Alarm"],
    "Light": [],
    "Occupancy Sensor": ["Heater", "Thermometer", "Air Conditioner", "Brightness Sensor"],
    "Thermometer": ["Fire Alarm"],
    "Fire Alarm": [],
    "Brightness Sensor": ["Light"],
    "Motion Sensor": ["Brightness Sensor", "Occupancy Sensor"],
    "Smoke Sensor": ["Fire Alarm"],
    "Media Player": ["Brightness Sensor", "Screen Projector", "Smart TV"],
    "Screen Projector": ["Smart TV"],
    "Smart TV": ["Speaker"],
    "Speaker": []

}

// list of all paths and their respective score (derived)

let pathlist = { "Humidity Sensor": [{ "totalpath": ["Humidity Sensor", "Ventilator"], "asp": 0.07898399999999997, "sr": 1.194, "cvss": 10.8, "ai": 7.2 }, { "totalpath": ["Humidity Sensor", "Air Conditioner"], "asp": 0.14375087999999994, "sr": 1.194, "cvss": 10.8, "ai": 7.2 }, { "totalpath": ["Humidity Sensor", "Heater"], "asp": 0.2588200368, "sr": 2.847, "cvss": 15.100000000000001, "ai": 9.5 }], "Ventilator": [{ "totalpath": ["Ventilator"], "asp": 0.17999999999999994, "sr": 0.648, "cvss": 5.5, "ai": 3.6 }], "CO2 Sensor": [{ "totalpath": ["CO2 Sensor", "Ventilator"], "asp": 0.03239999999999998, "sr": 1.296, "cvss": 11, "ai": 7.2 }], "Heater": [{ "totalpath": ["Heater"], "asp": 0.589836, "sr": 2.301, "cvss": 9.8, "ai": 5.9 }], "Window Sensor": [{ "totalpath": ["Window Sensor", "Heater"], "asp": 0.10617047999999997, "sr": 2.9490000000000003, "cvss": 15.3, "ai": 9.5 }, { "totalpath": ["Window Sensor", "Air Conditioner"], "asp": 0.05896799999999996, "sr": 1.296, "cvss": 11, "ai": 7.2 }], "Air Conditioner": [{ "totalpath": ["Air Conditioner"], "asp": 0.3275999999999999, "sr": 0.648, "cvss": 5.5, "ai": 3.6 }], "CO Detection Sensor": [{ "totalpath": ["CO Detection Sensor", "Fire Alarm"], "asp": 0.026207999999999978, "sr": 1.12, "cvss": 12.2, "ai": 9.5 }], "Occupancy Sensor": [{ "totalpath": ["Occupancy Sensor", "Heater"], "asp": 0.07078032, "sr": 2.4690000000000003, "cvss": 12.5, "ai": 7.300000000000001 }, { "totalpath": ["Occupancy Sensor", "Thermometer", "Fire Alarm"], "asp": 0.039311999999999986, "sr": 0.8160000000000001, "cvss": 8.2, "ai": 5 }, { "totalpath": ["Occupancy Sensor", "Air Conditioner"], "asp": 0.039311999999999986, "sr": 0.8160000000000001, "cvss": 8.2, "ai": 5 }], "Thermometer": [{ "totalpath": ["Thermometer", "Fire Alarm"], "asp": 0.3275999999999999, "sr": 0.648, "cvss": 5.5, "ai": 3.6 }], "Fire Alarm": [{ "totalpath": ["Fire Alarm"], "asp": 0.3275999999999999, "sr": 0.648, "cvss": 5.5, "ai": 3.6 }], "Motion Sensor": [{ "totalpath": ["Motion Sensor", "Occupancy Sensor", "Heater"], "asp": 0.027604324800000003, "sr": 3.873, "cvss": 20, "ai": 10.9 }, { "totalpath": ["Motion Sensor", "Occupancy Sensor", "Thermometer", "Fire Alarm"], "asp": 0.015331679999999995, "sr": 2.22, "cvss": 15.7, "ai": 8.6 }, { "totalpath": ["Motion Sensor", "Occupancy Sensor", "Air Conditioner"], "asp": 0.015331679999999995, "sr": 2.22, "cvss": 15.7, "ai": 8.6 }], "Smoke Sensor": [{ "totalpath": ["Smoke Sensor", "Fire Alarm"], "asp": 0.12776399999999996, "sr": 2.9490000000000003, "cvss": 15.3, "ai": 9.5 }], "Media Player": [{ "totalpath": ["Media Player", "Screen Projector", "Smart TV", "Speaker"], "asp": 0.014110704659519996, "sr": 4.974, "cvss": 26.3, "ai": 18.1 }, { "totalpath": ["Media Player", "Smart TV", "Speaker"], "asp": 0.028232702399999993, "sr": 2.673, "cvss": 19.6, "ai": 12.200000000000001 }], "Screen Projector": [{ "totalpath": ["Screen Projector", "Smart TV", "Speaker"], "asp": 0.0574540092, "sr": 4.3260000000000005, "cvss": 19.6, "ai": 12.200000000000001 }], "Smart TV": [{ "totalpath": ["Smart TV", "Speaker"], "asp": 0.114954, "sr": 2.0250000000000004, "cvss": 12.9, "ai": 6.300000000000001 }], "Speaker": [{ "totalpath": ["Speaker"], "asp": 0.4998, "sr": 1.4040000000000001, "cvss": 7.5, "ai": 3.6 }] }


totalpath = []


//helper function to find all path using recursion (quick implementation)
function findAllPaths(graph, start, path = []) {
    path.push(start);

    if (!(start in graph) || graph[start].length === 0) {

        totalpath.push(path.join(",").split(","))
    } else {
        for (const neighbor of graph[start]) {
            findAllPaths(graph, neighbor, path);
        }
    }

    path.pop()
}


// function to get all path and score them
function getAllpath() {

    for (const device in devicelist) {
        totalpath = []

        findAllPaths(devicelist, device);

        for (j in totalpath) {
            let asp = 1
            let ai = 0
            let ar = 0
            let cvss = 0
            let print = false
            for (i in totalpath[j]) {

                if (totalpath[j][i] in devicevuln) {
                    print = true

                    asp = devicevuln[totalpath[j][i]]['asp'] * asp
                    ai = devicevuln[totalpath[j][i]]['ai'] + ai
                    ar = devicevuln[totalpath[j][i]]['sr'] + ar
                    cvss = devicevuln[totalpath[j][i]]['cvss'] + cvss
                }
                else {
                    print = false;

                }


            }
            if (pathlist[device] && print == true) {
                pathlist[device].push({
                    totalpath: totalpath[j],
                    asp: asp,
                    sr: ar,
                    cvss: cvss,
                    ai, ai

                })

            }
            else {
                if (print == true) {
                    pathlist[device] = [{
                        totalpath: totalpath[j],
                        asp: asp,
                        sr: ar,
                        cvss: cvss,
                        ai, ai

                    }]
                }
            }

            if (print) {
                console.log(`Attack Path : ${totalpath[j].join('->')} Attack Success Probability : ${asp} Attack Impact: ${ai} Security Risk ${ar} CVSS ${cvss}`)
            }

        }
    }
    pathlist = JSON.stringify(pathlist)
    console.log(pathlist)
}


// calculates score for each vulnerability

function calculate_vuln_level() {
    data = Object.entries(device_vulnerabilities)
    console.log(data)
    for (i in data) {
        for (j in data[i][1]) {
            attack_Success = data[i][1][j]['Exploitability Score'] / 10
            attack_risk = attack_Success * data[i][1][j]['Impact Score']
            console.log(`Device Name : ${data[i][0]} Vulnerability ID : ${data[i][1][j]['Vulnerability ID']} Attack Success Probability : ${attack_Success} Attack Risk : ${attack_risk} Attack Impact : ${data[i][1][j]['Impact Score']} CVSS Base Score : ${data[i][1][j]['CVSS Score']} `)
        }
    }
}


// calculates score for each device/node

function calculate_device_level() {
    data = Object.entries(device_vulnerabilities)

    for (i in data) {
        asp = 1
        asp_or = 1
        ai = 0
        max_ai = 0
        ar = 0
        max_ar = 0
        cvss = 0
        max_cvss = 0
        for (j in data[i][1]) {

            attack_Success = data[i][1][j]['Exploitability Score'] / 10
            asp = asp * attack_Success
            asp_or = asp_or * (1 - attack_Success)
            attack_risk = attack_Success * data[i][1][j]['Impact Score']
            ai = ai + data[i][1][j]['Impact Score']
            if (data[i][1][j]['Impact Score'] > max_ai) {
                max_ai = data[i][1][j]['Impact Score']
            }
            ar = ar + attack_risk
            if (attack_risk > max_ar) {
                max_ar = attack_risk
            }
            cvss = cvss + data[i][1][j]['CVSS Score']
            if (data[i][1][j]['CVSS Score'] > max_cvss) {
                max_cvss = data[i][1][j]['CVSS Score']
            }
        }
        attack_success_or = 1 - asp_or

        attack_success_and = asp
        console.log(`Device Name : ${data[i][0]} Attack Success Probability : ${attack_success_or} Security Risk : ${max_ar} Attack Impact : ${max_ai} CVSS Base Score : ${max_cvss} Path : OR `)
        console.log(`Device Name : ${data[i][0]} Attack Success Probability : ${attack_success_and} Security Risk : ${ar} Attack Impact : ${ai} CVSS Base Score : ${cvss} Path : AND`)
        devicevuln[data[i][0]] = {
            asp: attack_success_or,
            sr: max_ar,
            ai: max_ai,
            cvss: max_cvss
        }



    }
    console.log(devicevuln)
}


// calculates score for the whole network

function calculate_network_level() {
    asp = 1
    max_ai = 0
    max_ar = 0
    max_cvss = 0
    for (i in pathlist) {

        for (j in pathlist[i]) {
            console.log(pathlist[i][j]['asp'])
            asp = asp * (1 - pathlist[i][j]['asp'])
            if (max_ai < pathlist[i][j]['ai']) {
                max_ai = pathlist[i][j]['ai']
            }
            if (max_ar < pathlist[i][j]['sr']) {
                max_ar = pathlist[i][j]['sr']
            }
            if (max_cvss < pathlist[i][j]['cvss']) {
                max_cvss = pathlist[i][j]['cvss']
            }


        }
    }
   
    console.log(`Attack Success Probability : ${1 - asp} Attack Impact: ${max_ai} Security Risk ${max_ar} CVSS ${max_cvss}`)

}

calculate_network_level()