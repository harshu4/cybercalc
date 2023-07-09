var neo4j = require('neo4j-driver');
(async () => {
    // URI examples: 'neo4j://localhost', 'neo4j+s://xxx.databases.neo4j.io'
    const URI = 'neo4j+s://6191f12f.databases.neo4j.io'
    const USER = 'neo4j'
    const PASSWORD = 'KNzHB4hY8xaJNtwPKtl2etW9w4RUwiHJFfAQkClw548'
    let driver;

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


    function findAllPaths(graph, start, path = []) {
        path.push(start);

        if (!(start in graph) || graph[start].length === 0) {
            console.log(path.join(" -> "));
        } else {
            for (const neighbor of graph[start]) {
                findAllPaths(graph, neighbor, path);
            }
        }

        path.pop();
    }



    let deviceVulnerabilities = {
        "Humidity Sensor": {
            "CVEs": [
                "CVE-2022-30339",
                "CVE-2022-46313"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-30339",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-46313"
            ]
        },
        "Ventilator": {
            "CVEs": [
                "CVE-2022-42756"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-42756"
            ]
        },
        "CO2 Sensor": {
            "CVEs": [
                "CVE-2022-39106"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39106"
            ]
        },
        "Heater": {
            "CVEs": [
                "CVE-2022-3575",
                "CVE-2022-39128",
                "CVE-2022-39127"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-3575",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39128",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39127"
            ]
        },
        "Window Sensor": {
            "CVEs": [
                "CVE-2022-39122"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39122"
            ]
        },
        "Air Conditioner": {
            "CVEs": [
                "CVE-2022-39121",
                "CVE-2022-39105"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39121",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39105"
            ]
        },
        "CO Detection Sensor": {
            "CVEs": [
                "CVE-2022-26474"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-26474"
            ]
        },
        "Light": {},
        "Occupancy Sensor": {
            "CVEs": [
                "CVE-2022-2841"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-2841"
            ]
        },
        "Thermometer": {},
        "Fire Alarm": {
            "CVEs": [
                "CVE-2022-39128",
                "CVE-2022-39127"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39128",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39127"
            ]
        },
        "Brightness Sensor": {
            "CVEs": [
                "CVE-2022-37063"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-37063"
            ]
        },
        "Motion Sensor": {
            "CVEs": [
                "CVE-2022-37062"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-37062"
            ]
        },
        "Smoke Sensor": {
            "CVEs": [
                "CVE-2022-37061"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-37061"
            ]
        },
        "Media Player": {
            "CVEs": [
                "CVE-2022-26474",
                "CVE-2022-39127"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-26474",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39127"
            ]
        },
        "Screen Projector": {
            "CVEs": [
                "CVE-2022-3575",
                "CVE-2022-39128"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-3575",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39128"
            ]
        },
        "Smart TV": {
            "CVEs": [
                "CVE-2022-37063"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-37063"
            ]
        },
        "Speaker": {
            "CVEs": [
                "CVE-2022-37062",
                "CVE-2022-39122"
            ],
            "Links": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-37062",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-39122"
            ]
        }
    }




    const createNodesAndRelationships = async () => {
        const session = driver.session();

        try {
            for (const [device, data] of Object.entries(deviceVulnerabilities)) {
                // Create device node
                await session.run(
                    'MERGE (device:Device {name: $device})',
                    { device }
                );



                // Create vulnerability nodes and attach them to the device
                if (data.CVEs) {
                    for (let i = 0; i < data.CVEs.length; i++) {
                        const cve = data.CVEs[i];
                        const link = data.Links[i];

                        await session.run(
                            `
                      MATCH (device:Device {name: $device})
            MERGE (v:Vulnerability {cve: $cve, link: $link})
            CREATE (v)-[r:AFFECTS]->(device)
            
            `,
                            { cve, link, device }
                        );

                    }
                }
            }
        } finally {
            // Close the session
            await session.close();
        }
    };

    async function connectNodes() {
        try {
            for (const [sourceNode, targetNodes] of Object.entries(devicelist)) {
                console.log(sourceNode)
                const sourceNodeId = await getNodeID(sourceNode);

                for (const targetNode of targetNodes) {
                    const targetNodeId = await getNodeID(targetNode);

                    await createRelationship(sourceNodeId, targetNodeId, 'CONNECTED_TO');
                }
            }

            console.log('Nodes connected successfully!');
        } catch (error) {
            console.error('Error connecting nodes:', error);
        } finally {
         
        }
    }

    // Define a function to retrieve the node ID based on the node label
    async function getNodeID(nodeLabel) {
        const session = driver.session();
        console.log(nodeLabel)
        const result = await session.run(
            'MATCH (a:Device WHERE a.name = $nodeLabel) RETURN ID(a) AS nodeId',
            { nodeLabel }
        );
      
        return result.records[0].get('nodeId');
    }

    // Define a function to create a relationship
    async function createRelationship(fromNodeId, toNodeId, relationshipType) {
        const session = driver.session();

        await session.run(
            `MATCH (fromNode), (toNode) WHERE ID(fromNode) = $fromNodeId AND ID(toNode) = $toNodeId
           CREATE (fromNode)-[r:${relationshipType}]->(toNode)`,
            { fromNodeId, toNodeId }
        );
    }


    try {
        driver = neo4j.driver(URI, neo4j.auth.basic(USER, PASSWORD))
        const serverInfo = await driver.getServerInfo()
        console.log('Connection established')
        console.log(serverInfo)
       //   await createNodesAndRelationships()
        // Example usage
        for (const device in devicelist) {
            console.log(`Paths from ${device}:`);
            findAllPaths(devicelist, device);
            console.log(); // Empty line for readability
        }
        connectNodes();

        console.log("done")
    } catch (err) {
        console.log(`Connection error\n${err}\nCause: ${err.cause}`)
    }
})();

