import { Hono } from 'hono'
import { convert } from "@sub-store-convert/core"

const app = new Hono()

app.get('/', (c) => {
    return c.redirect('https://github.com/TBXark/sub-store-convert', 302)
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
        const res = await convert(url, target, opts)
        return c.text(res, 200)
    } catch (e) {
        return c.text(e.message, 500)
    }
})

export default app
