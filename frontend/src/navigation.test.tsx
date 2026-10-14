// @vitest-environment jsdom
import React from 'react';
import {describe,it,expect,vi,afterEach} from 'vitest';
import {render,screen,fireEvent,cleanup,waitFor} from '@testing-library/react';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {api,defaultConfig} from './api';
import {App} from './main';
vi.mock('@xyflow/react',()=>({ReactFlow:()=>null,Background:()=>null,Controls:()=>null}));
vi.mock('recharts',()=>({AreaChart:()=>null,Area:()=>null,XAxis:()=>null,YAxis:()=>null,CartesianGrid:()=>null,Tooltip:()=>null,ResponsiveContainer:()=>null,BarChart:()=>null,Bar:()=>null,Cell:()=>null,ReferenceLine:()=>null}));
afterEach(()=>{cleanup();vi.restoreAllMocks()});
describe('authenticated navigation',()=>{
 it('opens all ten functional pages with empty backend state',async()=>{
  vi.spyOn(api,'get').mockImplementation(async(url:string)=>({data:url==='/auth/me'?{username:'analyst',role:'analyst',csrf:'test'}:url==='/settings'?defaultConfig:[]}));
  const q=new QueryClient({defaultOptions:{queries:{retry:false}}});
  render(<QueryClientProvider client={q}><App/></QueryClientProvider>);
  await screen.findByRole('heading',{name:'Security overview'});
  const pages=[['Upload Telemetry','Import recorded telemetry'],['Behavioral Analysis','Start an analysis to inspect behavior'],['File Correlation','File-centered evidence graph'],['Threat Detection','No scores yet'],['Alert Investigation','Investigation queue'],['Event Explorer','Event explorer'],['Evaluation Lab','Controlled comparison experiments'],['Reports','Export an investigation'],['Settings','Research configuration'],['Overview','Security overview']];
  for(const [name,heading] of pages){fireEvent.click(screen.getByRole('button',{name}));await screen.findByRole('heading',{name:heading})}
  q.clear();
 });
 it('renders validation and simulation controls without starting analysis implicitly',async()=>{
  const post=vi.spyOn(api,'post');vi.spyOn(api,'get').mockImplementation(async(url:string)=>({data:url==='/auth/me'?{username:'a',role:'analyst',csrf:'test'}:url==='/settings'?defaultConfig:[]}));
  const q=new QueryClient({defaultOptions:{queries:{retry:false}}});render(<QueryClientProvider client={q}><App/></QueryClientProvider>);
  await screen.findByRole('heading',{name:'Security overview'});fireEvent.click(screen.getByRole('button',{name:'Upload Telemetry'}));
  expect((screen.getByRole('button',{name:/Validate & preview/}) as HTMLButtonElement).disabled).toBe(true);expect(post).not.toHaveBeenCalled();q.clear();
 });
});
