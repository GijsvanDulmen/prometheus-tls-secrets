const winston = require('winston');
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const k8s = require('@kubernetes/client-node');
const client = require('prom-client');

let forge = require('node-forge');

// setup kubernetes
const kc = new k8s.KubeConfig();

if ( process.env.KUBERNETES_SERVICE_HOST ) {
    kc.loadFromCluster();
} else {
    kc.loadFromDefault();
}

// setup logger
const logger = winston.createLogger({
    level: 'info',
    transports: []
});

logger.add(new winston.transports.Console({
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.simple(),
    )
}));

// setup express
app.use(bodyParser.json());

app.get('/live', (req, res) => res.send("OK")); // live and readiness probe

const annotationPrefix = "expiration-watcher/";

const fetchInformation = () => {
    return new Promise((resolve, reject) => {
        const api = kc.makeApiClient(k8s.CoreV1Api);

        api.listSecretForAllNamespaces(true, null, 'type=kubernetes.io/tls').then(res => {
            let results = [];

            if ( res && res.body && res.body.items ) {
                res.body.items.forEach(item => {
                    // check if we need to watch
                    let watch = false;

                    if ( item.metadata && item.metadata.annotations ) {
                        // specific created secrets
                        if ( item.metadata.annotations[annotationPrefix+"watch"]
                            && item.metadata.annotations[annotationPrefix+"watch"] === "true" ) {
                                watch = true;
                        }

                        // watch cert-manager secrets as well
                        if ( item.metadata.annotations["cert-manager.io/common-name"] ) {
                            watch = true;
                        }
                    }

                    if ( !watch ) {
                        return;
                    }

                    const name = item.metadata.namespace+"/"+item.metadata.name;
                    logger.info("checking tls secret " + name);

                    if ( item.data["tls.crt"] ) {
                        logger.info("has certificate: " + name);

                        const decoded = forge.util.decode64(item.data["tls.crt"]);
                        const cert = forge.pki.certificateFromPem(decoded);

                        let certInfo = {
                            namespace: item.metadata.namespace,
                            name: item.metadata.name,
                            validity: cert.validity
                        };

                        if ( cert.issuer ) {
                            if ( cert.issuer.attributes ) {
                                cert.issuer.attributes.forEach(attr => {
                                    if ( attr.shortName === 'O' ) {
                                        certInfo.issuer = attr.value;
                                    }
                                });
                            }
                        }

                        if ( cert.subject ) {
                            if ( cert.subject.attributes ) {
                                cert.subject.attributes.forEach(attr => {
                                    if ( attr.shortName === 'CN' ) {
                                        certInfo.commonName = attr.value;
                                    }
                                });
                            }
                        }

                        if ( cert.extensions ) {
                            cert.extensions.forEach(extension => {
                                if ( extension.name == 'subjectAltName' ) {
                                    certInfo.altNames = extension.altNames.map(alt => alt.value);
                                }
                            });
                        }

                        results.push(certInfo);
                    }
                });
            }

            resolve(results);
        }).catch(err => {
            logger.error(err);
            reject();   
        });
    });
};

app.get('/json', (req, res, next) => {
    fetchInformation()
        .then(obj => res.send(obj))
        .catch(err => res.status(500).send("NOK"));
});

// setup prometheus
const gauge = new client.Gauge({
    name: 'expiration_days', help: 'expiration_days', labelNames: ['name', 'namespace', 'commonName', 'expirationDate']
});

const refreshInfo = () => {
    fetchInformation().then(secrets => {
        secrets.forEach(secret => {
            const diffInMillis = new Date(secret.validity.notAfter).getTime() - new Date().getTime();
            const diffInDays = Math.round(diffInMillis / (1000 * 3600 * 24));
            gauge.set({
                name: secret.name,
                namespace: secret.namespace,
                commonName: secret.commonName,
                expirationDate: secret.validity.notAfter
            }, diffInDays);
        });
    }).catch(err => logger.error(err));
};

// refresh every hour
setInterval(() => refreshInfo(), 1000*60*60);
refreshInfo();

app.get('/metrics', (req, res, next) => {
    res.set('Content-Type', client.register.contentType);
    res.end(client.register.metrics());
});

// starting
const port = 8080;
app.listen(port, () => {
    logger.info(`Started at at http://localhost:${port}`)
});