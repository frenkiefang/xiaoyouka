const allowedOrigin = Deno.env.get('ALLOWED_ORIGIN') ?? 'https://xiaoyouka.fffxc.xyz'

function corsHeaders(origin: string) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json; charset=utf-8',
    'Vary': 'Origin',
  }
}

function response(body: unknown, status: number, origin: string) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders(origin) })
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
}

Deno.serve(async (request) => {
  const origin = request.headers.get('origin') ?? ''
  if (origin !== allowedOrigin) {
    return new Response(JSON.stringify({ error: 'Origin is not allowed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Vary': 'Origin' },
    })
  }

  if (request.method === 'OPTIONS') {
    return response({ ok: true }, 200, origin)
  }
  if (request.method !== 'POST') {
    return response({ error: 'Method not allowed' }, 405, origin)
  }

  try {
    const payload = await request.json()
    const name = typeof payload?.name === 'string' ? payload.name.trim() : ''
    const visitorId = payload?.visitorId
    const pagePath = typeof payload?.pagePath === 'string' ? payload.pagePath : '/'

    if (
      !name ||
      name.length > 80 ||
      /[\x00-\x1F\x7F]/.test(name) ||
      !isUuid(visitorId) ||
      typeof pagePath !== 'string' ||
      !pagePath.startsWith('/') ||
      pagePath.length > 512 ||
      /[\x00-\x1F\x7F]/.test(pagePath)
    ) {
      return response({ error: 'Invalid visit payload' }, 400, origin)
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    if (!supabaseUrl || !serviceRoleKey) {
      console.error('Supabase server credentials are unavailable')
      return response({ error: 'Server configuration error' }, 500, origin)
    }

    const rpcResponse = await fetch(`${supabaseUrl}/rest/v1/rpc/record_name_visit`, {
      method: 'POST',
      headers: {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        p_name: name,
        p_visitor_id: visitorId,
        p_page_path: pagePath,
      }),
    })

    if (!rpcResponse.ok) {
      console.error('record_name_visit failed', await rpcResponse.text())
      return response({ error: 'Unable to record visit' }, 500, origin)
    }

    return response({ recorded: Boolean(await rpcResponse.json()) }, 200, origin)
  } catch (error) {
    console.error('record-name-visit failed', error)
    return response({ error: 'Invalid request' }, 400, origin)
  }
})
