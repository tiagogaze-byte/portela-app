
// portela.app — HUB Backend v2
// Reescrito com estrutura real das tabelas PostgreSQL

import express from 'express'
import cors from 'cors'
import pg from 'pg'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'

const { Pool } = pg
const app = express()
const PORT = process.env.HUB_PORT || 3003
const JWT_SECRET = process.env.JWT_SECRET || 'portela-hub-secret-2026'

// ── BANCO ──────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 })
pool.on('error', err => console.error('[DB] Pool error:', err.message))

// ── CACHE ──────────────────────────────────────────────
const cache = new Map()
function getCache(key) {
  const item = cache.get(key)
  if (!item) return null
  if (Date.now() - item.ts > 60000) { cache.delete(key); return null }
  return item.data
}
function setCache(key, data) { cache.set(key, { data, ts: Date.now() }) }

// ── CORS ───────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true, methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }))
app.use(express.json({ limit: '10mb' }))

// ── AUTH ───────────────────────────────────────────────
async function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim()
  if (!token) return res.status(401).json({ error: 'Token ausente' })
  try { req.user = jwt.verify(token, JWT_SECRET); next() }
  catch { return res.status(401).json({ error: 'Token inválido' }) }
}

// ── TRATAMENTO DE ERROS ────────────────────────────────
process.on('uncaughtException', err => console.error('[UNCAUGHT]', err.message))
process.on('unhandledRejection', err => console.error('[UNHANDLED]', err?.message))

// ══════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' })
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT id, email, nome, role, senha_hash FROM core.usuarios WHERE email = $1 AND ativo = true', [email.toLowerCase().trim()])
    const user = r.rows[0]
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' })
    const valid = await bcrypt.compare(password, user.senha_hash)
    if (!valid) return res.status(401).json({ error: 'Senha incorreta' })
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nome: user.nome }, JWT_SECRET, { expiresIn: '7d' })
    await client.query('UPDATE core.usuarios SET ultimo_acesso = NOW() WHERE id = $1', [user.id])
    return res.json({ token, user: { id: user.id, email: user.email, role: user.role, nome: user.nome } })
  } finally { client.release() }
})

app.post('/api/auth/register', async (req, res) => {
  const { email, password, nome, role } = req.body || {}
  if (!email || !password || !nome) return res.status(400).json({ error: 'Dados obrigatórios' })
  const client = await pool.connect()
  try {
    const existing = await client.query('SELECT id FROM core.usuarios WHERE email = $1', [email.toLowerCase().trim()])
    if (existing.rows.length) return res.status(409).json({ error: 'Email já cadastrado' })
    const hash = await bcrypt.hash(password, 10)
    const r = await client.query('INSERT INTO core.usuarios (email, nome, role, senha_hash, ativo) VALUES ($1,$2,$3,$4,true) RETURNING id, email, nome, role', [email.toLowerCase().trim(), nome, role || 'assessor', hash])
    return res.status(201).json({ user: r.rows[0] })
  } finally { client.release() }
})

app.get('/api/auth/me', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT id, email, nome, role, ultimo_acesso FROM core.usuarios WHERE id = $1', [req.user.id])
    if (!r.rows.length) return res.status(404).json({ error: 'Usuário não encontrado' })
    return res.json({ user: r.rows[0] })
  } finally { client.release() }
})

app.get('/api/auth/roles', auth, (req, res) => res.json({ roles: ['master', 'admin', 'assessor'] }))
app.post('/api/auth/roles', auth, async (req, res) => {
  if (!['master','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Sem permissão' })
  const { email, role } = req.body || {}
  const client = await pool.connect()
  try {
    await client.query('UPDATE core.usuarios SET role = $1 WHERE email = $2', [role, email])
    return res.json({ ok: true })
  } finally { client.release() }
})
app.delete('/api/auth/roles/:id', auth, (req, res) => res.json({ ok: true }))

// ── PROFILES ───────────────────────────────────────────
app.get('/api/profiles/:id', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT id, email, nome, role, ultimo_acesso FROM core.usuarios WHERE id = $1', [req.params.id])
    if (!r.rows.length) return res.status(404).json({ error: 'Perfil não encontrado' })
    return res.json({ profile: r.rows[0] })
  } finally { client.release() }
})
app.put('/api/profiles/:id', auth, async (req, res) => {
  const { nome, email } = req.body || {}
  const client = await pool.connect()
  try {
    await client.query('UPDATE core.usuarios SET nome=COALESCE($1,nome), email=COALESCE($2,email) WHERE id=$3', [nome, email, req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})
app.post('/api/profiles/:id/avatar', auth, (req, res) => res.json({ ok: true }))

// ── USERS ──────────────────────────────────────────────
app.get('/api/users', auth, async (req, res) => {
  if (!['master','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Sem permissão' })
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT id, email, nome, role, ativo, ultimo_acesso FROM core.usuarios ORDER BY created_at DESC')
    return res.json({ users: r.rows, total: r.rows.length })
  } finally { client.release() }
})
app.post('/api/users', auth, async (req, res) => {
  if (!['master','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Sem permissão' })
  const { email, nome, password, role } = req.body || {}
  if (!email || !nome || !password) return res.status(400).json({ error: 'Dados obrigatórios' })
  const client = await pool.connect()
  try {
    const hash = await bcrypt.hash(password, 10)
    const r = await client.query('INSERT INTO core.usuarios (email, nome, role, senha_hash, ativo) VALUES ($1,$2,$3,$4,true) RETURNING id, email, nome, role', [email.toLowerCase().trim(), nome, role || 'assessor', hash])
    return res.status(201).json({ user: r.rows[0] })
  } finally { client.release() }
})
app.put('/api/users/:id', auth, async (req, res) => {
  if (!['master','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Sem permissão' })
  const { role, ativo, nome } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query('UPDATE core.usuarios SET role=COALESCE($1,role), ativo=COALESCE($2,ativo), nome=COALESCE($3,nome) WHERE id=$4 RETURNING id, email, nome, role, ativo', [role, ativo, nome, req.params.id])
    return res.json({ user: r.rows[0] })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// MUNICÍPIOS
// ══════════════════════════════════════════════════════

app.get('/api/municipios', auth, async (req, res) => {
  const { include, limit = 100, offset = 0, search } = req.query
  const cacheKey = `municipios:${limit}:${offset}:${search || ''}:${include || ''}`
  const cached = getCache(cacheKey)
  if (cached) return res.json(cached)
  const client = await pool.connect()
  try {
    let q = `SELECT id, nome, regiao, codigo_ibge, status_atividade, populacao, 
             liderancas_ativas, assessor_id, votacao_ale, votacao_lincoln, 
             latitude, longitude, status_prefeito, idh, status_atendimento,
             tipo_atendimento, principal_demanda, observacao
             FROM hub.municipios WHERE 1=1`
    const params = []
    if (search) { params.push(`%${search}%`); q += ` AND nome ILIKE $${params.length}` }
    q += ` ORDER BY nome ASC LIMIT $${params.length+1} OFFSET $${params.length+2}`
    params.push(parseInt(limit), parseInt(offset))
    const r = await client.query(q, params)
    const countR = await client.query('SELECT COUNT(*) FROM hub.municipios' + (search ? ` WHERE nome ILIKE '%${search}%'` : ''))
    const result = { municipios: r.rows, total: parseInt(countR.rows[0].count), limit: parseInt(limit), offset: parseInt(offset) }
    setCache(cacheKey, result)
    return res.json(result)
  } finally { client.release() }
})

app.get('/api/municipios/:id', auth, async (req, res) => {
  const { include } = req.query
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT * FROM hub.municipios WHERE id = $1', [req.params.id])
    if (!r.rows.length) return res.status(404).json({ error: 'Município não encontrado' })
    const municipio = r.rows[0]
    if (include?.includes('demandas')) {
      const dem = await client.query('SELECT id, titulo, status, prioridade, created_at FROM hub.demandas WHERE municipio_id = $1 ORDER BY created_at DESC LIMIT 20', [municipio.id])
      municipio.demandas = dem.rows
    }
    if (include?.includes('liderancas')) {
      const lid = await client.query('SELECT id, nome, cargo, partido, telefone FROM hub.liderancas WHERE municipio_id = $1 ORDER BY nome ASC LIMIT 20', [municipio.id])
      municipio.liderancas = lid.rows
    }
    if (include?.includes('recursos')) {
      const rec = await client.query('SELECT id, tipo, descricao, valor, status FROM hub.recursos WHERE municipio_id = $1 ORDER BY created_at DESC LIMIT 20', [municipio.id])
      municipio.recursos = rec.rows
    }
    if (include?.includes('apoiadores')) {
      const ap = await client.query('SELECT id, nome, cargo, telefone FROM hub.apoiadores WHERE municipio_id = $1 ORDER BY nome ASC LIMIT 20', [municipio.id])
      municipio.apoiadores = ap.rows
    }
    return res.json({ municipio })
  } finally { client.release() }
})

app.post('/api/municipios', auth, async (req, res) => {
  const { nome, codigo_ibge, regiao, populacao, status_atividade, latitude, longitude } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query('INSERT INTO hub.municipios (nome, codigo_ibge, regiao, populacao, status_atividade, latitude, longitude) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [nome, codigo_ibge, regiao, populacao, status_atividade, latitude, longitude])
    cache.clear()
    return res.status(201).json({ municipio: r.rows[0] })
  } finally { client.release() }
})

app.put('/api/municipios/:id', auth, async (req, res) => {
  const fields = req.body || {}
  const client = await pool.connect()
  try {
    const sets = Object.keys(fields).map((k, i) => `${k} = $${i+1}`).join(', ')
    const vals = [...Object.values(fields), req.params.id]
    const r = await client.query(`UPDATE hub.municipios SET ${sets} WHERE id = $${vals.length} RETURNING *`, vals)
    cache.clear()
    return res.json({ municipio: r.rows[0] })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// LIDERANÇAS
// Colunas reais: id, nome, partido, cargo, municipio_nome, telefone, email, status,
//                created_at, origem, regiao, avatar_url, endereco, latitude, longitude,
//                municipio_id, votacao_ale, votacao_lincoln, principal_demanda,
//                sugestao_sedese, status_prefeito
// ══════════════════════════════════════════════════════

app.get('/api/liderancas', auth, async (req, res) => {
  const { municipio_id, regiao, status, limit = 50, offset = 0, search } = req.query
  const client = await pool.connect()
  try {
    let q = 'SELECT id, nome, partido, cargo, municipio_nome, municipio_id, telefone, email, status, regiao, avatar_url, origem FROM hub.liderancas WHERE 1=1'
    const params = []
    if (municipio_id) { params.push(municipio_id); q += ` AND municipio_id = $${params.length}` }
    if (regiao) { params.push(regiao); q += ` AND regiao = $${params.length}` }
    if (status) { params.push(status); q += ` AND status = $${params.length}` }
    if (search) { params.push(`%${search}%`); q += ` AND nome ILIKE $${params.length}` }
    q += ` ORDER BY nome ASC LIMIT $${params.length+1} OFFSET $${params.length+2}`
    params.push(parseInt(limit), parseInt(offset))
    const r = await client.query(q, params)
    const countR = await client.query('SELECT COUNT(*) FROM hub.liderancas')
    return res.json({ liderancas: r.rows, total: parseInt(countR.rows[0].count), limit: parseInt(limit), offset: parseInt(offset) })
  } finally { client.release() }
})

app.post('/api/liderancas', auth, async (req, res) => {
  const { nome, partido, cargo, municipio_nome, municipio_id, telefone, email, status, regiao, origem } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'INSERT INTO hub.liderancas (nome, partido, cargo, municipio_nome, municipio_id, telefone, email, status, regiao, origem) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
      [nome, partido, cargo, municipio_nome, municipio_id, telefone, email, status || 'ativo', regiao, origem]
    )
    return res.status(201).json({ lideranca: r.rows[0] })
  } finally { client.release() }
})

app.put('/api/liderancas/:id', auth, async (req, res) => {
  const { nome, partido, cargo, municipio_nome, telefone, email, status, regiao } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'UPDATE hub.liderancas SET nome=COALESCE($1,nome), partido=COALESCE($2,partido), cargo=COALESCE($3,cargo), municipio_nome=COALESCE($4,municipio_nome), telefone=COALESCE($5,telefone), email=COALESCE($6,email), status=COALESCE($7,status), regiao=COALESCE($8,regiao) WHERE id=$9 RETURNING *',
      [nome, partido, cargo, municipio_nome, telefone, email, status, regiao, req.params.id]
    )
    return res.json({ lideranca: r.rows[0] })
  } finally { client.release() }
})

app.delete('/api/liderancas/:id', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('DELETE FROM hub.liderancas WHERE id = $1', [req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// ASSESSORES
// Colunas reais: id, nome, email, telefone, regiao_atuacao, municipios_cobertos,
//                liderancas_gerenciadas, status, created_at, avatar_url, cargo,
//                latitude, longitude, origem, endereco, municipio_id, parlamentar_id
// ══════════════════════════════════════════════════════

app.get('/api/assessores', auth, async (req, res) => {
  const cached = getCache('assessores')
  if (cached) return res.json(cached)
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT id, nome, email, telefone, cargo, regiao_atuacao, municipios_cobertos, liderancas_gerenciadas, status, avatar_url, municipio_id FROM hub.assessores ORDER BY nome ASC')
    const result = { assessores: r.rows, total: r.rows.length }
    setCache('assessores', result)
    return res.json(result)
  } finally { client.release() }
})

app.post('/api/assessores', auth, async (req, res) => {
  const { nome, email, telefone, cargo, regiao_atuacao, municipio_id, status } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'INSERT INTO hub.assessores (nome, email, telefone, cargo, regiao_atuacao, municipio_id, status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [nome, email, telefone, cargo, regiao_atuacao, municipio_id, status || 'ativo']
    )
    cache.delete('assessores')
    return res.status(201).json({ assessor: r.rows[0] })
  } finally { client.release() }
})

app.put('/api/assessores/:id', auth, async (req, res) => {
  const { nome, email, telefone, cargo, regiao_atuacao, status } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'UPDATE hub.assessores SET nome=COALESCE($1,nome), email=COALESCE($2,email), telefone=COALESCE($3,telefone), cargo=COALESCE($4,cargo), regiao_atuacao=COALESCE($5,regiao_atuacao), status=COALESCE($6,status) WHERE id=$7 RETURNING *',
      [nome, email, telefone, cargo, regiao_atuacao, status, req.params.id]
    )
    cache.delete('assessores')
    return res.json({ assessor: r.rows[0] })
  } finally { client.release() }
})

app.delete('/api/assessores/:id', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('UPDATE hub.assessores SET status = $1 WHERE id = $2', ['inativo', req.params.id])
    cache.delete('assessores')
    return res.json({ ok: true })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// AGENDA
// Colunas reais: id, titulo, descricao, data, local, tipo, participantes,
//                created_at, origem, hora, privacidade, solicitacao_id,
//                parlamentar_id, municipio_id, divulgacao_status, solicita_divulgacao
// ══════════════════════════════════════════════════════

app.get('/api/agenda', auth, async (req, res) => {
  const { status, limit = 50, offset = 0 } = req.query
  const client = await pool.connect()
  try {
    let q = 'SELECT id, titulo, descricao, data, local, tipo, hora, privacidade, origem, parlamentar_id, municipio_id, divulgacao_status, solicita_divulgacao FROM hub.agenda WHERE 1=1'
    const params = []
    if (status) { params.push(status); q += ` AND divulgacao_status = $${params.length}` }
    q += ` ORDER BY data ASC LIMIT $${params.length+1} OFFSET $${params.length+2}`
    params.push(parseInt(limit), parseInt(offset))
    const r = await client.query(q, params)
    const countR = await client.query('SELECT COUNT(*) FROM hub.agenda')
    return res.json({ agenda: r.rows, total: parseInt(countR.rows[0].count), limit: parseInt(limit), offset: parseInt(offset) })
  } finally { client.release() }
})

app.post('/api/agenda', auth, async (req, res) => {
  const { titulo, descricao, data, local, tipo, hora, privacidade, parlamentar_id, municipio_id, solicita_divulgacao, origem } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'INSERT INTO hub.agenda (titulo, descricao, data, local, tipo, hora, privacidade, parlamentar_id, municipio_id, solicita_divulgacao, origem) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [titulo, descricao, data, local, tipo || 'reuniao', hora, privacidade || 'Público', parlamentar_id, municipio_id, solicita_divulgacao || false, origem]
    )
    return res.status(201).json({ evento: r.rows[0] })
  } finally { client.release() }
})

app.put('/api/agenda/:id', auth, async (req, res) => {
  const { titulo, descricao, data, local, tipo, hora, divulgacao_status } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'UPDATE hub.agenda SET titulo=COALESCE($1,titulo), descricao=COALESCE($2,descricao), data=COALESCE($3,data), local=COALESCE($4,local), tipo=COALESCE($5,tipo), hora=COALESCE($6,hora), divulgacao_status=COALESCE($7,divulgacao_status) WHERE id=$8 RETURNING *',
      [titulo, descricao, data, local, tipo, hora, divulgacao_status, req.params.id]
    )
    return res.json({ evento: r.rows[0] })
  } finally { client.release() }
})

app.delete('/api/agenda/:id', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('DELETE FROM hub.agenda WHERE id = $1', [req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})

app.get('/api/agenda/solicitacoes', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT * FROM hub.solicitacoes_agenda ORDER BY created_at DESC LIMIT 50')
    return res.json({ solicitacoes: r.rows })
  } finally { client.release() }
})

app.post('/api/agenda/solicitacoes', auth, async (req, res) => {
  const { titulo, data, hora_inicio, hora_fim, local, descricao, solicitante, origem, municipio_id } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'INSERT INTO hub.solicitacoes_agenda (id, titulo, data, hora_inicio, hora_fim, local, descricao, solicitante, origem, municipio_id) VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [titulo, data, hora_inicio, hora_fim, local, descricao, solicitante, origem, municipio_id]
    )
    return res.status(201).json({ solicitacao: r.rows[0] })
  } finally { client.release() }
})

app.put('/api/agenda/solicitacoes/:id/status', auth, async (req, res) => {
  const { status } = req.body || {}
  const client = await pool.connect()
  try {
    await client.query('UPDATE hub.solicitacoes_agenda SET status = $1 WHERE id = $2', [status, req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})

app.post('/api/agenda/solicitacoes/:id/approve', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('UPDATE hub.solicitacoes_agenda SET status = $1, data_aprovacao = NOW() WHERE id = $2', ['Aprovado', req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})

app.post('/api/agenda/solicitacoes/:id/undo-approve', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('UPDATE hub.solicitacoes_agenda SET status = $1 WHERE id = $2', ['Pendente', req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// RECURSOS
// Colunas reais: id, municipio_id, tipo, descricao, valor, origem,
//                status, data_aprovacao, responsavel, observacoes, created_at, parlamentar_id
// ══════════════════════════════════════════════════════

app.get('/api/recursos', auth, async (req, res) => {
  const { municipio_id, status, limit = 50, offset = 0 } = req.query
  const client = await pool.connect()
  try {
    let q = 'SELECT r.*, m.nome as municipio_nome FROM hub.recursos r LEFT JOIN hub.municipios m ON r.municipio_id = m.id WHERE 1=1'
    const params = []
    if (municipio_id) { params.push(municipio_id); q += ` AND r.municipio_id = $${params.length}` }
    if (status) { params.push(status); q += ` AND r.status = $${params.length}` }
    q += ` ORDER BY r.created_at DESC LIMIT $${params.length+1} OFFSET $${params.length+2}`
    params.push(parseInt(limit), parseInt(offset))
    const r = await client.query(q, params)
    const countR = await client.query('SELECT COUNT(*) FROM hub.recursos')
    return res.json({ recursos: r.rows, total: parseInt(countR.rows[0].count) })
  } finally { client.release() }
})

app.post('/api/recursos', auth, async (req, res) => {
  const { municipio_id, tipo, descricao, valor, origem, status, responsavel, observacoes } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'INSERT INTO hub.recursos (municipio_id, tipo, descricao, valor, origem, status, responsavel, observacoes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [municipio_id, tipo, descricao, valor, origem, status || 'Aprovado', responsavel, observacoes]
    )
    return res.status(201).json({ recurso: r.rows[0] })
  } finally { client.release() }
})

app.delete('/api/recursos/:id', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('DELETE FROM hub.recursos WHERE id = $1', [req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// DEMANDAS
// Colunas reais: id, municipio_id, titulo, descricao, status, prioridade,
//                created_at, origem, solicitante, recebido_por, atribuido_a,
//                redirecionado_para, area_responsavel, historico_redirecionamentos, parlamentar_id
// ══════════════════════════════════════════════════════

app.get('/api/demandas', auth, async (req, res) => {
  const { municipio_id, status, prioridade, limit = 50, offset = 0 } = req.query
  const client = await pool.connect()
  try {
    let q = 'SELECT id, municipio_id, titulo, descricao, status, prioridade, origem, solicitante, atribuido_a, area_responsavel, created_at FROM hub.demandas WHERE 1=1'
    const params = []
    if (municipio_id) { params.push(municipio_id); q += ` AND municipio_id = $${params.length}` }
    if (status) { params.push(status); q += ` AND status = $${params.length}` }
    if (prioridade) { params.push(prioridade); q += ` AND prioridade = $${params.length}` }
    q += ` ORDER BY created_at DESC LIMIT $${params.length+1} OFFSET $${params.length+2}`
    params.push(parseInt(limit), parseInt(offset))
    const r = await client.query(q, params)
    const countR = await client.query('SELECT COUNT(*) FROM hub.demandas')
    return res.json({ demandas: r.rows, total: parseInt(countR.rows[0].count) })
  } finally { client.release() }
})

app.get('/api/demandas/count', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT status, COUNT(*) as total FROM hub.demandas GROUP BY status')
    const counts = {}
    r.rows.forEach(row => { counts[row.status] = parseInt(row.total) })
    return res.json({ counts, total: r.rows.reduce((n, r) => n + parseInt(r.total), 0) })
  } finally { client.release() }
})

app.post('/api/demandas', auth, async (req, res) => {
  const { municipio_id, titulo, descricao, status, prioridade, solicitante, origem, atribuido_a, area_responsavel } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'INSERT INTO hub.demandas (municipio_id, titulo, descricao, status, prioridade, solicitante, origem, atribuido_a, area_responsavel) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [municipio_id, titulo, descricao, status || 'aberta', prioridade || 'normal', solicitante, origem, atribuido_a, area_responsavel]
    )
    return res.status(201).json({ demanda: r.rows[0] })
  } finally { client.release() }
})

app.put('/api/demandas/:id', auth, async (req, res) => {
  const { titulo, status, prioridade, descricao, atribuido_a, area_responsavel } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'UPDATE hub.demandas SET titulo=COALESCE($1,titulo), status=COALESCE($2,status), prioridade=COALESCE($3,prioridade), descricao=COALESCE($4,descricao), atribuido_a=COALESCE($5,atribuido_a), area_responsavel=COALESCE($6,area_responsavel) WHERE id=$7 RETURNING *',
      [titulo, status, prioridade, descricao, atribuido_a, area_responsavel, req.params.id]
    )
    return res.json({ demanda: r.rows[0] })
  } finally { client.release() }
})

app.delete('/api/demandas/:id', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('DELETE FROM hub.demandas WHERE id = $1', [req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// APOIADORES
// Colunas reais: id, municipio_id, nome, cargo, telefone, endereco, email,
//                foto_url, created_at, status_prefeito, votacao_ale,
//                votacao_lincoln, principal_demanda, sugestao_sedese
// ══════════════════════════════════════════════════════

app.get('/api/apoiadores', auth, async (req, res) => {
  const { municipio_id, limit = 50, offset = 0, search } = req.query
  const client = await pool.connect()
  try {
    let q = 'SELECT id, municipio_id, nome, cargo, telefone, email, foto_url, status_prefeito, votacao_ale, votacao_lincoln FROM hub.apoiadores WHERE 1=1'
    const params = []
    if (municipio_id) { params.push(municipio_id); q += ` AND municipio_id = $${params.length}` }
    if (search) { params.push(`%${search}%`); q += ` AND nome ILIKE $${params.length}` }
    q += ` ORDER BY nome ASC LIMIT $${params.length+1} OFFSET $${params.length+2}`
    params.push(parseInt(limit), parseInt(offset))
    const r = await client.query(q, params)
    const countR = await client.query('SELECT COUNT(*) FROM hub.apoiadores')
    return res.json({ apoiadores: r.rows, total: parseInt(countR.rows[0].count) })
  } finally { client.release() }
})

app.post('/api/apoiadores', auth, async (req, res) => {
  const { municipio_id, nome, cargo, telefone, email, endereco } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'INSERT INTO hub.apoiadores (municipio_id, nome, cargo, telefone, email, endereco) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [municipio_id, nome, cargo, telefone, email, endereco]
    )
    return res.status(201).json({ apoiador: r.rows[0] })
  } finally { client.release() }
})

app.put('/api/apoiadores/:id', auth, async (req, res) => {
  const { nome, cargo, telefone, email, status_prefeito } = req.body || {}
  const client = await pool.connect()
  try {
    const r = await client.query(
      'UPDATE hub.apoiadores SET nome=COALESCE($1,nome), cargo=COALESCE($2,cargo), telefone=COALESCE($3,telefone), email=COALESCE($4,email), status_prefeito=COALESCE($5,status_prefeito) WHERE id=$6 RETURNING *',
      [nome, cargo, telefone, email, status_prefeito, req.params.id]
    )
    return res.json({ apoiador: r.rows[0] })
  } finally { client.release() }
})

app.delete('/api/apoiadores/:id', auth, async (req, res) => {
  const client = await pool.connect()
  try {
    await client.query('DELETE FROM hub.apoiadores WHERE id = $1', [req.params.id])
    return res.json({ ok: true })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// NOTIFICAÇÕES
// ══════════════════════════════════════════════════════

app.get('/api/notificacoes', auth, async (req, res) => {
  return res.json({ notificacoes: [], total: 0 })
})
app.put('/api/notificacoes/:id/read', auth, (req, res) => res.json({ ok: true }))
app.post('/api/notificacoes', auth, (req, res) => res.status(201).json({ ok: true }))
app.get('/api/notification-logs', auth, (req, res) => res.json({ logs: [], total: 0 }))

// ══════════════════════════════════════════════════════
// PARLAMENTARES
// ══════════════════════════════════════════════════════

app.get('/api/parlamentares', auth, async (req, res) => {
  const cached = getCache('parlamentares')
  if (cached) return res.json(cached)
  const client = await pool.connect()
  try {
    const r = await client.query('SELECT * FROM hub.parlamentares ORDER BY nome ASC')
    const result = { parlamentares: r.rows }
    setCache('parlamentares', result)
    return res.json(result)
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// VOTOS
// ══════════════════════════════════════════════════════

app.get('/api/votos', auth, async (req, res) => {
  const { municipio_id, limit = 50, offset = 0 } = req.query
  const client = await pool.connect()
  try {
    let q = 'SELECT v.*, m.nome as municipio FROM hub.votos v LEFT JOIN hub.municipios m ON v.municipio_id = m.id WHERE 1=1'
    const params = []
    if (municipio_id) { params.push(municipio_id); q += ` AND v.municipio_id = $${params.length}` }
    q += ` ORDER BY v.ano DESC LIMIT $${params.length+1} OFFSET $${params.length+2}`
    params.push(parseInt(limit), parseInt(offset))
    const r = await client.query(q, params)
    return res.json({ votos: r.rows, total: r.rows.length })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// SYNC
// ══════════════════════════════════════════════════════

app.post('/api/sync/bulk-municipios', auth, async (req, res) => {
  const { municipios } = req.body || {}
  if (!municipios?.length) return res.status(400).json({ error: 'Dados obrigatórios' })
  const client = await pool.connect()
  let inserted = 0, updated = 0
  try {
    await client.query('BEGIN')
    for (const m of municipios) {
      const existing = await client.query('SELECT id FROM hub.municipios WHERE codigo_ibge = $1', [m.codigo_ibge])
      if (existing.rows.length) {
        await client.query('UPDATE hub.municipios SET nome=$1, populacao=$2, regiao=$3 WHERE codigo_ibge=$4', [m.nome, m.populacao, m.regiao, m.codigo_ibge])
        updated++
      } else {
        await client.query('INSERT INTO hub.municipios (nome, codigo_ibge, populacao, regiao) VALUES ($1,$2,$3,$4)', [m.nome, m.codigo_ibge, m.populacao, m.regiao])
        inserted++
      }
    }
    await client.query('COMMIT')
    cache.clear()
    return res.json({ ok: true, inserted, updated })
  } catch(e) {
    await client.query('ROLLBACK')
    return res.status(500).json({ error: e.message })
  } finally { client.release() }
})

app.post('/api/sync/bulk-apoiadores', auth, async (req, res) => {
  const { apoiadores } = req.body || {}
  if (!apoiadores?.length) return res.status(400).json({ error: 'Dados obrigatórios' })
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    for (const a of apoiadores) {
      await client.query('INSERT INTO hub.apoiadores (nome, telefone, municipio_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [a.nome, a.telefone, a.municipio_id])
    }
    await client.query('COMMIT')
    return res.json({ ok: true, total: apoiadores.length })
  } catch(e) {
    await client.query('ROLLBACK')
    return res.status(500).json({ error: e.message })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// INTEGRAÇÕES (placeholders)
// ══════════════════════════════════════════════════════

app.get('/api/integrations/google-calendar', auth, (req, res) => res.json({ ok: true, events: [] }))
app.post('/api/integrations/twilio-broadcast', auth, (req, res) => res.json({ ok: true }))

// ══════════════════════════════════════════════════════
// ADMIN SQL (master only)
// ══════════════════════════════════════════════════════

app.post('/api/admin/sql', auth, async (req, res) => {
  if (req.user.role !== 'master') return res.status(403).json({ error: 'Sem permissão' })
  const { sql } = req.body || {}
  if (!sql) return res.status(400).json({ error: 'SQL obrigatório' })
  const client = await pool.connect()
  try {
    const r = await client.query(sql)
    cache.clear()
    return res.json({ ok: true, command: r.command, rowCount: r.rowCount, rows: r.rows })
  } catch(e) {
    return res.status(400).json({ error: e.message })
  } finally { client.release() }
})

// ══════════════════════════════════════════════════════
// HEALTH
// ══════════════════════════════════════════════════════

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1')
    res.json({ ok: true, service: 'portela-hub', db: 'connected' })
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message })
  }
})

// ── START ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════╗`)
  console.log(`║  portela.app — HUB Backend v2          ║`)
  console.log(`║  Porta: ${PORT}                           ║`)
  console.log(`╚════════════════════════════════════════╝\n`)
  pool.query('SELECT NOW()').then(r => console.log(`✅ [DB] Conectado — ${r.rows[0].now}`))
})
