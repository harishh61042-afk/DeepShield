import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

type PriorityCount = { name: string; findings: number }

export default function SeverityChart({ data }: { data: PriorityCount[] }) {
  const colors: Record<string, string> = { Critical: '#a84238', High: '#c26a36', Medium: '#9a7900', Low: '#5d7d62', Unknown: '#81838a' }
  return <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><BarChart data={data} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}><CartesianGrid strokeDasharray="4 4" vertical={false} stroke="var(--border)" /><XAxis dataKey="name" tickLine={false} axisLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} /><YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} /><Tooltip cursor={{ fill: 'var(--hover)' }} contentStyle={{ borderRadius: 12, border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)' }} /><Bar dataKey="findings" radius={[6, 6, 0, 0]} maxBarSize={48}>{data.map(item => <Cell key={item.name} fill={colors[item.name] || 'var(--primary-ink)'} />)}</Bar></BarChart></ResponsiveContainer></div>
}
