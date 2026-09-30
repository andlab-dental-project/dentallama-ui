import { NextRequest, NextResponse } from 'next/server'

import { timingSafeEqual } from 'crypto'

export const dynamic = 'force-dynamic'

const KEEPALIVE_EMAIL = 'keepalive@healthcheck.invalid'
const KEEPALIVE_PASSWORD = 'keepalive-health-check'

function getSupabaseCredentials(): { url: string; anonKey: string } | null {
  const url = process.env.SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL
  const anonKey =
    process.env.SUPABASE_ANON_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

  if (!url || !anonKey) return null

  return { url: url.replace(/\/$/, ''), anonKey }
}

function isCronAuthorized(request: NextRequest): boolean {
  const secret = process.env.CRON_SECRET
  if (!secret) return false

  const header = request.headers.get('authorization') ?? ''
  const expected = `Bearer ${secret}`
  const providedBuffer = Buffer.from(header)
  const expectedBuffer = Buffer.from(expected)

  if (providedBuffer.length !== expectedBuffer.length) return false

  return timingSafeEqual(providedBuffer, expectedBuffer)
}

/**
 * GoTrue looks up auth.users before rejecting these credentials, so the
 * request is a real Postgres read. /auth/v1/health returns 200 without
 * touching the database and does not reset the inactivity timer.
 */
async function pingSupabase(
  url: string,
  anonKey: string
): Promise<{ ok: boolean; status: number }> {
  const response = await fetch(`${url}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: {
      apikey: anonKey,
      Authorization: `Bearer ${anonKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: KEEPALIVE_EMAIL,
      password: KEEPALIVE_PASSWORD
    }),
    cache: 'no-store',
    redirect: 'manual'
  })

  await response.arrayBuffer()

  return {
    ok: response.status === 400 || response.status === 200,
    status: response.status
  }
}

export async function GET(request: NextRequest) {
  if (!process.env.CRON_SECRET) {
    console.error('[supabase-health] CRON_SECRET is not configured')
    return NextResponse.json(
      { ok: false, error: 'CRON_SECRET is not configured' },
      { status: 500 }
    )
  }

  if (!isCronAuthorized(request)) {
    return NextResponse.json(
      { ok: false, error: 'Unauthorized' },
      { status: 401 }
    )
  }

  const credentials = getSupabaseCredentials()
  if (!credentials) {
    console.error(
      '[supabase-health] Supabase URL or anon key is not configured'
    )
    return NextResponse.json(
      { ok: false, error: 'Supabase is not configured' },
      { status: 500 }
    )
  }

  try {
    const result = await pingSupabase(credentials.url, credentials.anonKey)

    if (!result.ok) {
      console.error(`[supabase-health] unexpected status ${result.status}`)
      return NextResponse.json(
        { ok: false, status: result.status },
        { status: 502 }
      )
    }

    console.log(`[supabase-health] ok status=${result.status}`)
    return NextResponse.json({
      ok: true,
      status: result.status,
      checkedAt: new Date().toISOString()
    })
  } catch (error) {
    console.error('[supabase-health] request failed', error)
    return NextResponse.json(
      { ok: false, error: 'Supabase request failed' },
      { status: 502 }
    )
  }
}
