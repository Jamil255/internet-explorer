import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import Explorer from '@/components/Explorer';
import { LESSONS, getLesson } from '@/lessons';

export function generateStaticParams() {
  return LESSONS.map((l) => ({ id: l.id }));
}

export function generateMetadata({ params }: { params: { id: string } }): Metadata {
  const l = getLesson(params.id);
  return l ? { title: `${l.name} · ${l.title} — Network Explorer`, description: l.overview.description } : {};
}

export default function LessonPage({ params }: { params: { id: string } }) {
  if (!getLesson(params.id)) notFound();
  return <Explorer initialId={params.id} />;
}
