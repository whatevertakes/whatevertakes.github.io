import { defineCollection } from 'astro:content';
import { file, glob } from 'astro/loaders';
import { z } from 'astro/zod';

// WT 인프라 지도 데이터 (src/content/infra/).
// 공개 자료만 둔다. 미공개 취약점·탐색 결과는 이 저장소에 넣지 않는다.
// 파일 이름(확장자 제외)이 ID이고, 다른 파일은 그 ID로 참조한다.
// 참조 무결성은 src/lib/infra-data.ts 가 빌드 때 검사하며, 깨지면 빌드가 실패한다.

const base = './src/content/infra';
const byFileName = ({ entry }: { entry: string }) => entry.replace(/\.ya?ml$/, '');
const areaId = z.string().regex(/^(?:[1-9]|1[0-6])$/, '영역 ID는 "1"~"16" 문자열');
const day = z.union([z.string(), z.date()]).transform((v) => (v instanceof Date ? v.toISOString().slice(0, 10) : v));
const year = z.union([z.string(), z.number()]).transform(String);

const areas = defineCollection({
  loader: file(`${base}/areas.yaml`),
  schema: z.object({
    name: z.string(),
    en: z.string(),
    bounty: z.enum(['hi', 'mid', 'lo']),
    summary: z.string(),
    korea: z.string(),
    oss: z.array(z.string()),
    questions: z.object({ operator: z.string(), attacker: z.string(), defender: z.string() }),
    links: z.array(z.string()),
  }),
});

const links = defineCollection({
  loader: file(`${base}/links.yaml`),
  schema: z.object({ title: z.string(), url: z.string().url() }),
});

const oss = defineCollection({
  loader: glob({ pattern: '*.yaml', base: `${base}/oss`, generateId: byFileName }),
  schema: z.object({ name: z.string(), areas: z.array(areaId).min(1) }),
});

const vulns = defineCollection({
  loader: glob({ pattern: 'CVE-*.yaml', base: `${base}/vulns`, generateId: byFileName }),
  schema: z.object({
    summary: z.string(),
    areas: z.array(areaId).min(1),
    // base: 영역의 기본기 목록, recent: 최신 실제 악용(KEV) 목록, none: 사건 등에서만 참조
    list: z.enum(['base', 'recent', 'none']),
    kev: z.object({ date: day, ransomware: z.boolean() }).optional(),
    cvss: z.object({ score: z.number().min(0).max(10), version: z.string(), source: z.string() }).optional(),
  }),
});

const incidents = defineCollection({
  loader: glob({ pattern: '*.yaml', base: `${base}/incidents`, generateId: byFileName }),
  schema: z.object({
    title: z.string(),
    date: year,
    summary: z.string(),
    areas: z.array(areaId).min(1),
    notes: z.record(areaId, z.string()).optional(),
    recent: z.boolean(),
    status: z.enum(['confirmed', 'reported', 'denied']),
    sources: z.array(z.string().url()),
    vulns: z.array(z.string()).optional(),
  }),
});

const companies = defineCollection({
  loader: glob({ pattern: '*.yaml', base: `${base}/companies`, generateId: byFileName }),
  schema: z.object({
    name: z.string(),
    region: z.enum(['kr', 'global']),
    order: z.number(),
    tag: z.string(),
    services: z.array(z.object({ name: z.string(), areas: z.array(areaId).min(1) })),
    infra: z.string(),
    incidents: z.array(z.object({ date: year, text: z.string(), areas: z.array(areaId), source: z.string().url().optional() })),
    bounty: z.object({ status: z.enum(['yes', 'no', 'unknown']), note: z.string(), url: z.string().url().optional() }),
    tip: z.string(),
    blog: z.string().url().optional(),
    deep: z
      .object({
        summary: z.string(),
        facts: z.array(z.object({ label: z.string(), value: z.string(), detail: z.string() })),
        services: z.array(z.object({ name: z.string(), areas: z.record(areaId, z.enum(['core', 'related'])) })),
        areas: z.record(areaId, z.object({ here: z.string(), risk: z.string(), study: z.string(), sources: z.array(z.object({ title: z.string(), url: z.string().url() })) })),
        timeline: z.array(z.object({ date: year, text: z.string(), bad: z.boolean().optional() })),
        use: z.array(z.object({ title: z.string(), style: z.enum(['ul', 'ol']), items: z.array(z.string()), note: z.string() })),
      })
      .optional(),
  }),
});

// 기업이 어떤 오픈소스를 쓰는지에 대한 공개 근거. 파일 이름: <company>__<oss>.yaml
const usage = defineCollection({
  loader: glob({ pattern: '*.yaml', base: `${base}/usage`, generateId: byFileName }),
  schema: z.object({
    company: z.string(),
    oss: z.string(),
    confidence: z.enum(['confirmed', 'likely', 'inferred']),
    checked: day,
    evidence: z.array(z.object({ title: z.string(), url: z.string().url() })).min(1),
  }),
});

export const collections = { areas, links, oss, vulns, incidents, companies, usage };
