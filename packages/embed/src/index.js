import { preprocessors, loadProducer, parseProxyLines, produceOutput } from '@sub-store-convert/core'

globalThis.SubConvert = {
    convert(raw, target, optsJSON) {
        const producer = loadProducer(target)
        if (!producer) throw new Error(`Unknown target: ${target}`)
        let lines = null
        for (const p of preprocessors) {
            try {
                if (p.test(raw)) {
                    lines = p.parse(raw).split('\n').map(l => l.trim()).filter(Boolean)
                    break
                }
            } catch (e) {}
        }
        if (!lines) lines = raw.split('\n').map(l => l.trim()).filter(Boolean)
        const opts = optsJSON ? JSON.parse(optsJSON) : {}
        return produceOutput(producer, parseProxyLines(lines, opts))
    },
}
