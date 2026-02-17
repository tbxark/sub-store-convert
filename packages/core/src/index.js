import parsersImport from  './vendors/Sub-Store/backend/src/core/proxy-utils/parsers/index.js'
import produceImport from './vendors/Sub-Store/backend/src/core/proxy-utils/producers/index.js'
import preprocessorsImport from './vendors/Sub-Store/backend/src/core/proxy-utils/preprocessors/index.js'

export const parsers = parsersImport;
export const produce = produceImport;
export const preprocessors = preprocessorsImport;

/**
 * Find and load the producer for the target format
 * @param {string} target - Target format name
 * @returns {Object|null} Producer object or null
 */
export function loadProducer(target) {
    const targetLower = target.toLowerCase()
    for (const key of Object.keys(produce)) {
        if (key.toLowerCase() === targetLower) {
            return produce[key]
        }
    }
    return null
}

/**
 * Load and preprocess proxy data from remote URL
 * @param {string} url - Remote subscription URL
 * @returns {Promise<string[]>} Array of processed proxy lines
 */
export async function loadRemoteData(url) {
    try {
        const response = await fetch(url)
        const raw = await response.text()
        
        for (const preprocessor of preprocessors) {
            try {
                if (preprocessor.test(raw)) {
                    return preprocessor.parse(raw)
                        .split('\n')
                        .map(line => line.trim())
                        .filter(line => line.length > 0)
                }
            } catch (error) {
                console.error('Preprocessor error:', error)
            }
        }
        return []
    } catch (error) {
        console.error('Failed to load remote data:', error)
        return []
    }
}

/**
 * Try to parse proxy line using specified parser
 * @param {Object} parser - Parser object
 * @param {string} line - Proxy configuration line
 * @returns {Object|null} Parsed proxy object or null
 */
export function tryParseProxy(parser, line) {
    try {
        if (parser.test(line)) {
            return parser.parse(line)
        }
    } catch (error) {
        console.error('Parser test/parse error:', error)
    }
    return null
}

/**
 * Build proxy server object
 * @param {Object} proxy - Raw proxy object
 * @param {Object} opts - Additional options
 * @returns {Object} Merged proxy object
 */
export function buildProxyServer(proxy, opts) {
    const server = { ...proxy, ...opts }
    if (server.name) {
        server.name = server.name.trim()
    }
    return server
}

/**
 * Parse proxy line list
 * @param {string[]} lines - Array of proxy configuration lines
 * @param {Object} opts - Additional options
 * @returns {Object[]} Array of proxy objects
 */
export function parseProxyLines(lines, opts) {
    const proxyList = []
    let lastParser = null

    for (const line of lines) {
        if (line.length === 0) continue

        let proxy = null

        // Prefer using the last successful parser
        if (lastParser) {
            proxy = tryParseProxy(lastParser, line)
            if (proxy) {
                proxyList.push(buildProxyServer(proxy, opts))
                continue
            }
        }

        // Iterate through all parsers to try parsing
        for (const parser of parsers) {
            proxy = tryParseProxy(parser, line)
            if (proxy) {
                proxyList.push(buildProxyServer(proxy, opts))
                lastParser = parser
                break
            }
        }
    }

    return proxyList
}

/**
 * Generate target format using producer
 * @param {Object} producer - Producer object
 * @param {Object[]} proxyList - Array of proxy objects
 * @returns {string} Generated configuration text
 */
export function produceOutput(producer, proxyList) {
    if (producer.type === 'ALL') {
        return producer.produce(proxyList)
    }

    const results = []
    for (const proxy of proxyList) {
        try {
            results.push(producer.produce(proxy, proxy.type))
        } catch (error) {
            console.error('Producer error:', error)
        }
    }
    return results.join('\n')
}

/**
 * Convert subscription URL to target format
 * @param {string} url - Subscription URL (supports multiple URLs separated by |)
 * @param {string} target - Target format
 * @param {Object} opts - Additional options
 * @returns {Promise<string>} Converted configuration text
 */
export async function convert(url, target, opts = {}) {
    const producer = loadProducer(target)
    if (!producer) {
        throw new Error(`Unknown target: ${target}`)
    }

    // Load all subscription URLs in parallel
    const urls = url.split('|')
    const allLines = await Promise.all(urls.map(loadRemoteData))
    const lines = allLines.flat()

    // Parse proxy list
    const proxyList = parseProxyLines(lines, opts)

    // Generate target format output
    return produceOutput(producer, proxyList)
}