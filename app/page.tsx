'use client';

import { useState } from 'react';
import { ExternalLink, FileVideo, ShieldCheck } from 'lucide-react';

const learningItems = [
  'Packet Tracer로 네트워크망 구성하기',
  '방화벽을 붙이고 허용/차단 규칙 나눠보기',
  '일부러 장애를 만들고 로그와 메모로 원인 확인하기',
];

const strengths = [
  {
    title: '끈기 있게 원인을 좁힙니다',
    situation:
      'Packet Tracer에서 방화벽 규칙을 넣었는데 통신이 예상대로 되지 않는 상황이 있었습니다.',
    action:
      '케이블 연결, IP, 게이트웨이, 허용/차단 규칙 순서를 하나씩 다시 확인했습니다.',
    result:
      '문제가 생긴 지점을 좁혀 가며 설정을 고쳤고, 동작 과정을 영상과 메모로 남겼습니다.',
    evidence: '연결 근거: Packet Tracer 실습 파일과 작동 확인 영상',
  },
  {
    title: '실수해도 다시 시도합니다',
    situation:
      '설정 실수나 반복되는 오류 때문에 자신감이 떨어지는 순간이 있었습니다.',
    action:
      '같은 실수를 줄이기 위해 확인한 내용과 로그를 메모하고 다시 시도했습니다.',
    result:
      '다음에 봐야 할 순서가 생겼고, 막혔던 부분을 다시 확인할 수 있었습니다.',
    evidence: '연결 근거: 장애 확인 메모와 로그 캡처 기록',
  },
  {
    title: '과정을 남겨 결과로 만듭니다',
    situation:
      '실습 결과만 남겨 두면 나중에 어떤 순서로 해결했는지 다시 떠올리기 어려웠습니다.',
    action:
      '일부러 장애를 만들고, 로그와 화면 캡처를 보면서 원인과 확인 내용을 메모했습니다.',
    result:
      '아직 완성본은 아니지만, 네트워크 구성과 보안 설정 과정을 포트폴리오로 정리할 자료가 생겼습니다.',
    evidence: '연결 근거: 미완성 포트폴리오 자료와 실습 기록',
  },
];

const publicScope = ['이름', '배우고 있는 네트워크 내용', '공개 가능한 실습 기록'];
const privateScope = ['개인 주소', '계정 정보', '가족과 지인 정보'];

const qualityChecks = [
  {
    issue: '움직임 선택권이 없었습니다.',
    before: '페이지 안 이동 링크가 부드럽게 움직였지만 사용자가 줄일 방법은 보이지 않았습니다.',
    after: '첫 화면에 움직임 줄이기 버튼을 추가해 부드러운 이동을 끌 수 있게 했습니다.',
  },
  {
    issue: '상호작용이 영상 재생 외에는 부족했습니다.',
    before: '소개 내용은 읽을 수 있었지만 사용자가 펼쳐 확인하는 항목은 없었습니다.',
    after: '강점 카드에 확인 방법을 펼치는 항목을 추가해 마우스와 키보드로 열 수 있게 했습니다.',
  },
  {
    issue: '제출 전 확인 방법이 분리되어 있지 않았습니다.',
    before: '어디로 가서 무엇을 보면 통과인지 한눈에 확인하기 어려웠습니다.',
    after: '확인 위치, 3단계 행동, 통과 화면, 안 될 때 보이는 상태를 따로 적었습니다.',
  },
];

export default function Home() {
  const [reducedMotion, setReducedMotion] = useState(false);

  function toggleMotion() {
    const next = !reducedMotion;
    setReducedMotion(next);
    document.documentElement.classList.toggle('reduce-motion', next);
  }

  return (
    <main className="min-h-screen bg-[var(--background)] text-[var(--foreground)]">
      <section className="mx-auto grid min-h-screen w-full max-w-7xl grid-cols-[1.05fr_0.95fr] gap-8 px-5 py-6 md:px-10 lg:px-14">
        <div className="flex flex-col justify-between gap-8">
          <nav
            aria-label="페이지 바로가기"
            className="flex flex-wrap items-center gap-3 text-sm font-medium text-slate-600"
          >
            <a href="#intro">소개</a>
            <a href="#learning">배우는 것</a>
            <a href="#work">작업물</a>
            <a href="#video">영상</a>
            <a href="#privacy">공개 범위</a>
            <a href="#checks">점검</a>
          </nav>

          <div id="intro" className="space-y-6">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-teal-700">
              T01 · 나를 소개하는 한 페이지
            </p>
            <div className="space-y-4">
              <h1 className="max-w-3xl text-4xl font-bold leading-[1.1] text-slate-950 md:text-6xl">
                스스로 길을 찾으며 보안 네트워크를 배우는 함찬원입니다.
              </h1>
              <p className="max-w-2xl text-lg leading-8 text-slate-700">
                그동안은 현장에서 일하며 제 길을 찾아왔고, 지금은
                보안·네트워크 엔지니어를 목표로 Packet Tracer 실습 포트폴리오를
                만들고 있습니다.
              </p>
            </div>

            <button className="motion-toggle" type="button" onClick={toggleMotion}>
              {reducedMotion ? '부드러운 이동 켜기' : '움직임 줄이기'}
            </button>

            <div className="grid gap-3 sm:grid-cols-3">
              <div className="info-tile">
                <span>보여줄 대상</span>
                <strong>강사님 · 조원분들</strong>
              </div>
              <div className="info-tile">
                <span>지금 배우는 것</span>
                <strong>네트워크 구성 · 방화벽 규칙</strong>
              </div>
              <div className="info-tile">
                <span>나를 보여주는 근거</span>
                <strong>실습 파일 · 로그 메모 · 영상</strong>
              </div>
            </div>
          </div>

          <section id="learning" className="panel">
            <h2>지금 배우고 있는 것</h2>
            <ul className="check-list">
              {learningItems.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        </div>

        <aside
          id="work"
          className="flex flex-col justify-between gap-6 rounded-lg border border-slate-200 bg-white p-5 shadow-sm"
        >
          <div className="space-y-5">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-teal-700">작업물</p>
                <h2 className="mt-2 text-3xl font-bold text-slate-950">
                  보안 네트워크망 실습
                  <span className="ml-2 inline-block rounded bg-amber-100 px-2 py-1 align-middle text-sm font-semibold text-amber-900">
                    미완성
                  </span>
                </h2>
              </div>
              <FileVideo aria-hidden="true" className="mt-1 h-8 w-8 text-teal-700" />
            </div>

            <p className="leading-7 text-slate-700">
              보안 네트워크망을 개설한 뒤 방화벽을 설치하고, 허용망과 거부망을
              추가해 본 실습입니다. 일부러 버그를 발생시켜 로그를 캡처하고
              메모하면서 문제를 확인했습니다.
            </p>

            <div className="rounded-lg bg-slate-950 p-4 font-mono text-sm text-slate-100">
              <p>작업 파일 묶음</p>
              <p className="mt-3 text-teal-200">
                보안 네트워크망 구성 + 방화벽 허용/거부 규칙 실습
              </p>
              <p className="text-slate-300">
                네트워크망 성공.pkt · 방화벽 설치 및 허용,차단 규칙.pkt
              </p>
              <p className="mt-3 text-amber-200">
                미완성인 이유: 캡처와 메모를 정리해 최종 포트폴리오 문서로 묶는
                과정이 남아 있습니다.
              </p>
            </div>
          </div>

          <a className="work-button" href="#video">
            <span>작동 영상 보기 (미완성)</span>
            <ExternalLink aria-hidden="true" className="h-5 w-5" />
          </a>
        </aside>
      </section>

      <section className="section-wrap">
        <div className="section-heading">
          <p>나를 설명하는 세 가지</p>
          <h2>실습하면서 알게 된 내 방식</h2>
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          {strengths.map((strength, index) => (
            <article className="strength-card" key={strength.title}>
              <span>{String(index + 1).padStart(2, '0')}</span>
              <h3>{strength.title}</h3>
              <dl>
                <div>
                  <dt>상황</dt>
                  <dd>{strength.situation}</dd>
                </div>
                <div>
                  <dt>행동</dt>
                  <dd>{strength.action}</dd>
                </div>
                <div>
                  <dt>결과</dt>
                  <dd>{strength.result}</dd>
                </div>
              </dl>
              <p className="evidence-text">{strength.evidence}</p>
              {index === 0 ? (
                <details className="check-method">
                  <summary>짧은 확인 방법</summary>
                  <ol>
                    <li>작업물 영역으로 갑니다.</li>
                    <li>작동 영상 보기 버튼을 누르고 영상 영역을 확인합니다.</li>
                    <li>영상과 미완성 설명이 보이면 통과입니다.</li>
                  </ol>
                  <p>안 될 때는 영상 영역이 비어 있거나 재생할 수 없다는 문장이 보입니다.</p>
                </details>
              ) : null}
            </article>
          ))}
        </div>
      </section>

      <section id="video" className="section-wrap pt-0">
        <div className="video-panel">
          <div className="section-heading">
            <p>작동 확인</p>
            <h2>Packet Tracer 실습 영상</h2>
          </div>
          <video
            className="work-video"
            controls
            preload="metadata"
            src="https://raw.githubusercontent.com/gkacksdnjs22-stack/chanwon-network-practice/e8e628b896074fb4c1c76cabba30b9387258e380/public/packet-tracer-demo-unfinished.mp4"
          >
            이 브라우저에서는 영상을 재생할 수 없습니다.
          </video>
          <p>
            이 영상은 완성 발표물이 아니라, 실습이 실제로 동작하는지 확인하기
            위해 남긴 미완성 기록입니다.
          </p>
        </div>
      </section>

      <section id="privacy" className="section-wrap pt-0">
        <div className="privacy-note">
          <ShieldCheck aria-hidden="true" className="h-7 w-7 text-teal-700" />
          <div>
            <h2>공개 범위</h2>
            <p>
              이 페이지는 강사님과 조원분들에게 제가 네트워크 실습을 하며 문제를
              확인하고 기록하는 방식을 보여주기 위해 만들었습니다.
            </p>
            <div className="scope-grid">
              <div>
                <strong>공개한 내용</strong>
                <ul>
                  {publicScope.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>제외한 내용</strong>
                <ul>
                  {privateScope.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="checks" className="section-wrap pt-0">
        <div className="section-heading">
          <p>제출 전 점검</p>
          <h2>링크와 접근성 확인 기록</h2>
        </div>
        <div className="quality-grid">
          {qualityChecks.map((check) => (
            <article className="quality-card" key={check.issue}>
              <h3>{check.issue}</h3>
              <p>
                <strong>수정 전</strong>
                {check.before}
              </p>
              <p>
                <strong>수정 후</strong>
                {check.after}
              </p>
            </article>
          ))}
        </div>
        <div className="submit-note">
          <div>
            <h3>최종 확인</h3>
            <p>
              링크는 각 섹션으로 이동하고, Tab 키로 메뉴와 버튼, 펼치기 항목을
              순서대로 이동할 수 있습니다. 브라우저 콘솔의 빨간 오류는 0건으로
              확인했습니다.
            </p>
          </div>
          <div>
            <h3>AI 사용 구분</h3>
            <p>
              AI에게는 문장 정리와 접근성 점검을 맡겼고, 공개할 내용과 제외할
              개인정보, 실습 작업물의 범위는 학생이 직접 판단했습니다. 따르지
              않은 제안은 과제 내용과 맞지 않는 계획표를 페이지에 크게 넣는
              방식이었고, 대신 미완성 이유 한 줄만 남겼습니다.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
