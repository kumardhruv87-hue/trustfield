"""Generate the deliberately-vulnerable test fixture app.

Run: `python tools/make_fixtures.py` from the project root.
The fixture is a fake Next.js + Supabase + OpenAI + Stripe app that contains
every class of mistake ShipProof claims to catch. All keys are invented.
"""
from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "vulnerable-app"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def fake_service_role_jwt() -> str:
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(
        json.dumps(
            {"role": "service_role", "iss": "supabase", "ref": "abcdefghijklmnopq", "iat": 1730000000}
        ).encode()
    )
    return f"{header}.{payload}.q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6"


FILES: dict[str, str] = {}


def build() -> None:
    jwt = fake_service_role_jwt()
    # Synthetic detector input, generated without embedding a credential in Git.
    stripe_fixture = "sk_" + "live_" + "1" * 24

    FILES[".env"] = f"""# committed by accident — this is exactly what vibe coding does at 2am
OPENAI_API_KEY=sk-proj-aB3dE9fG2hJ5kL8mN1pQ4rS7tU0vW3xY6zA9
SUPABASE_URL=https://abcdefghijklmnopq.supabase.co
SUPABASE_SERVICE_ROLE_KEY={jwt}
STRIPE_SECRET_KEY={stripe_fixture}
DATABASE_URL=postgresql://postgres:hunter2@db.abcdefghijklmnopq.supabase.co:5432/postgres
"""

    FILES[".gitignore"] = """node_modules
.next
dist
"""

    FILES["package.json"] = json.dumps(
        {
            "name": "vibe-app",
            "private": True,
            "scripts": {"dev": "next dev", "build": "next build"},
            "dependencies": {
                "next": "14.2.3",
                "@supabase/supabase-js": "2.45.0",
                "openai": "4.60.0",
                "stripe": "16.0.0",
                "lodash": "4.17.20",
            },
        },
        indent=2,
    )

    FILES["next.config.js"] = """/** @type {import('next').NextConfig} */
const nextConfig = { reactStrictMode: true };
module.exports = nextConfig;
"""

    FILES["app/page.tsx"] = """'use client';

import { createClient } from '@supabase/supabase-js';

// The AI put the admin client inside a client component.
const admin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

export default function Page() {
  return <main>My vibe-coded app</main>;
}
"""

    FILES["app/api/chat/route.ts"] = """import OpenAI from 'openai';

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const cors = { origin: '*' };

export async function POST(req: Request) {
  const { messages } = await req.json();
  const completion = await client.chat.completions.create({
    model: 'gpt-4o-mini',
    messages,
  });
  return Response.json({ text: completion.choices[0].message.content });
}
"""

    FILES["app/api/webhook/route.ts"] = """export async function POST(req: Request) {
  const body = await req.json();
  if (body.type === 'checkout.session.completed') {
    // mark the user as paid — no signature check anywhere
    console.log('paid', body.data.object.customer_email);
  }
  return Response.json({ received: true });
}
"""

    FILES["app/api/admin/route.ts"] = """import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function GET() {
  const { data } = await supabase.from('users').select('*');
  return Response.json(data);
}
"""

    FILES["lib/supabase.ts"] = f"""import {{ createClient }} from '@supabase/supabase-js';

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);

// service role key hardcoded "temporarily" in March
export const admin = createClient(
  process.env.SUPABASE_URL!,
  '{jwt}'
);
"""

    FILES["lib/db.ts"] = """import { admin } from './supabase';

export async function getUser(id: string) {
  // string-concatenated SQL
  const rows = await admin.rpc('exec_sql', { sql: `select * from users where id = '${id}'` });
  console.log('token', process.env.SUPABASE_SERVICE_ROLE_KEY);
  return rows;
}
"""

    FILES["supabase/migrations/001_init.sql"] = """-- created by an AI, reviewed by nobody
create table public.users (
  id uuid primary key default gen_random_uuid(),
  email text
);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.users(id),
  total integer
);

alter table public.users enable row level security;
-- no policy was ever written for public.users either
"""

    FILES["README.md"] = """# vibe-app

Test fixture for ShipProof. Every credential here is invented.
"""

    FIXTURE.mkdir(parents=True, exist_ok=True)
    for name, content in FILES.items():
        path = FIXTURE / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(f"wrote {len(FILES)} fixture files to {FIXTURE}")


if __name__ == "__main__":
    if FIXTURE.exists():
        shutil.rmtree(FIXTURE)
    build()
