import { Hono } from 'hono'
import { convert } from "@sub-store-convert/core"

const app = new Hono()

app.get('/', (c) => {
    return c.redirect('https://github.com/tbxark/sub-store-convert', 302)
})

app.get('/sub', async (c) => {
    const opts = c.req.query()
    const target = opts.target
    const url = opts.url
    if (!target || !url) {
        return c.text('Missing target or url', 400)
    }
    delete opts.target
    delete opts.url
    try {
        for (const key in opts) {
            const val = opts[key]
            if (typeof val !== 'string') continue
            if (val === 'true') {
                opts[key] = true
            } else if (val === 'false') {
                opts[key] = false
            } else if (val !== '' && val.trim() !== '' && !isNaN(val)) {
                opts[key] = Number(val)
            }
        }
        const res = await convert(url, target, opts)
        return c.text(res, 200)
    } catch (e) {
        const msg = e instanceof Error ? e.message : String(e)
        return c.text(msg, 500)
    }
})

export default app
