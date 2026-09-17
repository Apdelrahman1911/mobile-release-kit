import { useId } from 'react';
import { blockingAncestor, getValue } from '../catalog.ts';
import type { FieldContext, FieldHelp, HelpContent, JsonObject, JsonValue } from '../types.ts';
import { HelpButton } from './Common.tsx';
import { Icon } from './Icon.tsx';

interface FieldProps {
  field: FieldHelp;
  draft: JsonObject;
  context?: FieldContext;
  contextFresh?: boolean;
  onChange: (path: string, value: JsonValue | undefined) => void;
  onHelp: (help: HelpContent) => void;
}

function StringList({ value, label, onChange, tokens = false }: { value: string[]; label: string; onChange: (value: string[]) => void; tokens?: boolean }) {
  return <div className={`list-editor${tokens ? ' token-editor' : ''}`}>
    {value.length === 0 && <span className="empty-list">{tokens ? 'No arguments configured' : 'No entries configured'}</span>}
    {value.map((item, index) => <div className="list-editor-row" key={index}><span className="list-index">{tokens ? index : index + 1}</span><input type="text" aria-label={`${label}, ${tokens ? 'argument' : 'entry'} ${index + 1}`} value={item} autoComplete="off" spellCheck={false} onChange={(event) => onChange(value.map((entry, offset) => offset === index ? event.target.value : entry))} /><button type="button" className="icon-button" aria-label={`Remove ${label} ${tokens ? 'argument' : 'entry'} ${index + 1}`} onClick={() => onChange(value.filter((_, offset) => offset !== index))}><Icon name="close" size={15} /></button></div>)}
    <button type="button" className="text-button add-entry" onClick={() => onChange([...value, ''])}><Icon name="plus" size={15} />{tokens ? 'Add argument' : 'Add entry'}</button>
  </div>;
}

function hasInputShape(field: FieldHelp, value: JsonValue | undefined): boolean {
  if (value === undefined) return true;
  if (field.input === 'boolean') return typeof value === 'boolean';
  if (field.input === 'number') return typeof value === 'number';
  if (field.input === 'string-list' || field.input === 'argv') return Array.isArray(value) && value.every((item) => typeof item === 'string');
  if (field.input === 'commands') return Array.isArray(value) && value.every((command) => Array.isArray(command) && command.every((token) => typeof token === 'string'));
  return typeof value === 'string';
}

export function DraftField({ field, draft, context, contextFresh = false, onChange, onHelp }: FieldProps) {
  const id = useId();
  const descriptionId = `${id}-description`;
  const value = getValue(draft, field.path);
  const parent = blockingAncestor(draft, field.path);
  const invalidShape = !hasInputShape(field, value);
  const update = (next: JsonValue | undefined) => onChange(field.path, next);
  const showClear = value !== undefined;
  const isList = ['string-list', 'argv', 'commands'].includes(field.input);
  const presence = value === undefined ? 'Not set' : value === null ? 'Explicit null' : value === '' ? 'Empty string' : Array.isArray(value) && value.length === 0 ? 'Empty list' : 'Set';
  const contextLabel = contextFresh && context ? context.state === 'forbidden' ? 'Not allowed here' : context.state === 'unknown' ? 'Context unknown' : context.state : context ? 'Review is stale' : 'Context not reviewed';
  let control;
  if (parent) {
    control = <div id={id} className="unsupported-value" role="status">The parent <code>{parent}</code> has a non-object value. It is preserved; this child control cannot replace or remove it.</div>;
  } else if (invalidShape) {
    control = <div id={id} className="unsupported-value" role="status">The value has a different type than this field expects. It is preserved until you explicitly unset it or discard the draft.</div>;
  } else if (field.input === 'enum' || field.input === 'boolean') {
    const selected = value === undefined ? '' : String(value);
    const options = field.input === 'boolean' ? ['true', 'false'] : field.options ?? [];
    control = <select id={id} aria-describedby={descriptionId} value={selected} onChange={(event) => update(event.target.value === '' ? undefined : field.input === 'boolean' ? event.target.value === 'true' : event.target.value)}><option value="">Not set</option>{selected && !options.includes(selected) && <option value={selected}>{selected} (unrecognized)</option>}{options.map((option) => <option key={option} value={option}>{field.input === 'boolean' ? option === 'true' ? 'Enabled / Yes' : 'Disabled / No' : option}</option>)}</select>;
  } else if (field.input === 'string-list' || field.input === 'argv') {
    control = <StringList value={(value ?? []) as string[]} label={field.label} tokens={field.input === 'argv'} onChange={update} />;
  } else if (field.input === 'commands') {
    const commands = (value ?? []) as string[][];
    control = <div className="commands-editor">{commands.length === 0 && <span className="empty-list">No commands configured</span>}{commands.map((command, index) => <div className="command-editor" key={index}><div className="command-heading"><strong>Command {index + 1}</strong><button type="button" className="text-button" onClick={() => update(commands.filter((_, offset) => index !== offset))}>Remove command {index + 1}</button></div><StringList value={command} label={`${field.label}, command ${index + 1}`} tokens onChange={(tokens) => update(commands.map((entry, offset) => offset === index ? tokens : entry))} /></div>)}<button type="button" className="text-button add-entry" onClick={() => update([...commands, []])}><Icon name="plus" size={15} />Add command</button><p className="field-safety"><Icon name="lock" size={13} />Arguments are draft text. Nothing will be executed.</p></div>;
  } else {
    control = <input id={id} type={field.input === 'number' ? 'number' : 'text'} value={typeof value === 'string' || typeof value === 'number' ? value : ''} autoComplete="off" spellCheck={false} aria-describedby={descriptionId} placeholder={typeof field.example === 'string' ? `e.g. ${field.example}` : 'Not configured'} onChange={(event) => update(field.input === 'number' ? event.target.value === '' ? undefined : Number(event.target.value) : event.target.value)} />;
  }
  return <div className={`form-field${isList ? ' full-width' : ''}`} role={isList ? 'group' : undefined} aria-labelledby={isList ? `${id}-label` : undefined} aria-describedby={isList ? descriptionId : undefined}>
    <div className="field-label-row"><label id={`${id}-label`} htmlFor={isList ? undefined : id}>{field.label}</label><HelpButton content={field} onHelp={onHelp} /><span className={`requiredness ${contextFresh && context ? context.state : 'unreviewed'}`}>{contextLabel}</span></div>
    {control}
    <div className="field-bottom"><p id={descriptionId}>{field.what}</p>{showClear && <button type="button" className="clear-field" aria-label={`Unset ${field.label} in this draft and retain an undo copy`} onClick={() => update(undefined)}>Unset</button>}</div>
    <div className="field-context"><span className="field-presence">{parent ? 'Parent needs review' : presence}</span>{contextFresh && context && <p className={context.state === 'forbidden' && context.present || context.state === 'unknown' ? 'context-warning' : ''}>{context.reason}{context.state === 'forbidden' && context.present ? ' Your value is retained until you explicitly unset it.' : ''}</p>}</div>
  </div>;
}
