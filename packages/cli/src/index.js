#!/usr/bin/env node
import { createInterface } from 'node:readline/promises'
import { stdin as input, stdout as output } from 'node:process'
import { convert } from '@sub-store-convert/core'

const DEFAULT_TARGET = 'surge'

async function main() {
    const rl = createInterface({ input, output })

    let url = process.argv[2]
    if (!url) {
        url = (await rl.question('URL: ')).trim()
    }
    if (!url) {
        rl.close()
        console.error('URL is required')
        process.exit(1)
    }

    const answer = (await rl.question(`Target [${DEFAULT_TARGET}]: `)).trim()
    rl.close()

    const target = answer.length > 0 ? answer : DEFAULT_TARGET

    const result = await convert(url, target)
    output.write(result)
    output.write('\n')
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err))
    process.exit(1)
})
