/* NOVA X frontend — same-origin API only; no secrets or third-party libraries. */
(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const state = {
    health: null,
    authenticated: false,
    authRequired: false,
    tasks: [],
    goals: [],
    selectedTaskId: null,
    editingGoalId: null,
    conversationId: sessionStorage.getItem('novaConversationId') || null,
    currentView: 'command',
    pollTimer: null,
    taskTimer: null,
    busy: false,
    models: [],
    providers: [],
    modes: [],
    selectedModelIds: (() => { try { return JSON.parse(localStorage.getItem('novaSelectedModelIds') || '[]'); } catch (_error) { return []; } })(),
    defaultMode: 'balanced',
    modelLimits: { max_models_per_fusion: 3 },
    editingModelId: null,
    catalogProfileId: null,
    autonomyPolicy: null,
  };

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[ch]);
  }

  function formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
  }

  function friendlyState(value) {
    return String(value || 'queued').replaceAll('_', ' ');
  }

  function toast(message, isError = false) {
    const node = document.createElement('div');
    node.className = `toast${isError ? ' error' : ''}`;
    node.textContent = message;
    $('#toastRegion').appendChild(node);
    window.setTimeout(() => node.remove(), 4300);
  }

  function showAuth(message = '') {
    $('#authOverlay').classList.remove('hidden');
    $('#authError').textContent = message;
    $('#authToken').focus();
  }

  function closeAuth() {
    $('#authOverlay').classList.add('hidden');
    $('#authToken').value = '';
    $('#authError').textContent = '';
  }

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    let response;
    try {
      response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
    } catch (_error) {
      throw new Error('Could not reach the NOVA server. Check the connection and try again.');
    }
    const data = await response.json().catch(() => ({}));
    if (response.status === 401 && state.authRequired) {
      showAuth('Your session expired. Sign in again.');
      throw new Error('Authentication required.');
    }
    if (!response.ok) {
      let detail = typeof data.detail === 'string' ? data.detail : (data.detail?.message || `Request failed (${response.status}).`);
      if (Array.isArray(data.detail?.models) && data.detail.models.length) {
        const attempts = data.detail.models.map(item => `${item.name || item.model_id || 'model'}: ${item.status || 'unknown'}${item.error ? ` (${item.error})` : ''}${item.retry_after_seconds != null ? `; retry after ${Number(item.retry_after_seconds).toFixed(1)}s` : ''}`).join('; ');
        detail += ` Actual model attempts: ${attempts}.`;
      }
      throw new Error(detail);
    }
    return data;
  }

  function setText(selector, value) {
    const node = $(selector);
    if (node) node.textContent = value;
  }

  // Progressive enhancement: index.html ships a static fallback for both of
  // these, so a no-JS or pre-hydration render still looks intentional.
  function renderTodayLabel() {
    const node = $('#todayLabel');
    if (!node) return;
    const now = new Date();
    if (Number.isNaN(now.getTime())) return;
    node.textContent = now
      .toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' })
      .toUpperCase();
  }

  function switchView(name) {
    const allowed = ['command', 'tasks', 'goals', 'tools', 'models', 'settings'];
    if (!allowed.includes(name)) return;
    state.currentView = name;
    $$('.view').forEach(view => view.classList.toggle('active', view.id === `view-${name}`));
    $$('.nav-item').forEach(item => {
      const active = item.dataset.view === name;
      item.classList.toggle('active', active);
      if (active) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
    });
    const titles = { command: 'Command center', tasks: 'Tasks & plans', goals: 'Goals & schedules', tools: 'Tools', models: 'Models & intelligence', settings: 'Settings' };
    setText('#pageTitle', titles[name]);
    $('#sidebar').classList.remove('open');
    if (name === 'tasks') loadTasks(true).catch(err => toast(err.message, true));
    if (name === 'goals') loadGoals().catch(err => toast(err.message, true));
    if (name === 'tools') loadTools().catch(err => toast(err.message, true));
    if (name === 'models') loadModelDashboard().catch(err => toast(err.message, true));
    if (name === 'settings') {
      loadUsage().catch(() => {});
      loadAutonomyPolicy().catch(err => toast(err.message, true));
      loadSetup().catch(err => toast(err.message, true));
    }
  }

  function appendMessage(role, text, isError = false) {
    const welcome = $('#welcomeMessage');
    if (welcome) welcome.remove();
    const message = document.createElement('article');
    message.className = `chat-message ${role === 'user' ? 'user' : 'assistant'}${isError ? ' message-error' : ''}`;
    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = role === 'user' ? 'Y' : 'N';
    const body = document.createElement('div');
    body.className = 'message-body';
    const meta = document.createElement('div');
    meta.className = 'message-meta';
    meta.textContent = role === 'user' ? 'You' : (isError ? 'NOVA · notice' : 'NOVA X');
    const content = document.createElement('div');
    content.className = 'message-text';
    content.textContent = String(text ?? '');
    body.append(meta, content);
    message.append(avatar, body);
    $('#chatLog').appendChild(message);
    $('#chatLog').scrollTop = $('#chatLog').scrollHeight;
    return message;
  }

  function showTyping() {
    const welcome = $('#welcomeMessage');
    if (welcome) welcome.remove();
    const node = document.createElement('div');
    node.className = 'chat-message assistant';
    node.id = 'typingIndicator';
    node.innerHTML = '<div class="message-avatar">N</div><div class="message-body"><div class="message-meta">NOVA X · thinking</div><div class="message-text chat-thinking"><i></i><i></i><i></i></div></div>';
    $('#chatLog').appendChild(node);
    $('#chatLog').scrollTop = $('#chatLog').scrollHeight;
  }

  function removeTyping() {
    const node = $('#typingIndicator');
    if (node) node.remove();
  }

  async function loadConversation() {
    if (!state.conversationId) return;
    try {
      const data = await api(`/api/conversations/${encodeURIComponent(state.conversationId)}/messages?limit=40`);
      if (!data.messages || !data.messages.length) return;
      $('#chatLog').innerHTML = '';
      for (const message of data.messages) appendMessage(message.role, message.content);
    } catch (_error) {
      state.conversationId = null;
      sessionStorage.removeItem('novaConversationId');
    }
  }

  async function sendChat() {
    const input = $('#messageInput');
    const text = input.value.trim();
    if (!text || state.busy) return;
    state.busy = true;
    input.value = '';
    appendMessage('user', text);
    showTyping();
    $('#chatForm button[type="submit"]').disabled = true;
    try {
      const data = await api('/api/chat', {
        method: 'POST',
        body: JSON.stringify({
          message: text,
          conversation_id: state.conversationId,
          intelligence_mode: currentMode(),
          model_ids: [...state.selectedModelIds],
        }),
      });
      state.conversationId = data.conversation_id;
      sessionStorage.setItem('novaConversationId', state.conversationId);
      removeTyping();
      const assistant = appendMessage('assistant', data.message?.content || 'The provider returned an empty response.');
      renderIntelligenceMetadata(assistant, data.intelligence || {});
    } catch (error) {
      removeTyping();
      appendMessage('assistant', error.message, true);
    } finally {
      state.busy = false;
      $('#chatForm button[type="submit"]').disabled = false;
      input.focus();
    }
  }

  async function createTask() {
    const input = $('#messageInput');
    const objective = input.value.trim();
    if (!objective || state.busy) {
      if (!objective) { input.focus(); toast('Enter an objective first.'); }
      return;
    }
    state.busy = true;
    try {
      const task = await api('/api/tasks', {
        method: 'POST',
        body: JSON.stringify({
          objective,
          review_plan: $('#reviewPlanToggle').checked,
          intelligence_mode: currentMode(),
          model_ids: [...state.selectedModelIds],
        }),
      });
      input.value = '';
      $('#reviewPlanToggle').checked = false;
      toast('Task queued. NOVA will show its plan, tool calls, and verification status.');
      state.selectedTaskId = task.id;
      await loadTasks(true);
      switchView('tasks');
      await loadTaskDetail(task.id);
    } catch (error) {
      toast(error.message, true);
    } finally {
      state.busy = false;
    }
  }

  function taskCard(task, selected = false, compact = false) {
    const title = escapeHtml(task.objective);
    const label = escapeHtml(friendlyState(task.state));
    return `<div class="${compact ? 'recent-task' : 'task-card'}${selected ? ' selected' : ''}" data-task-id="${escapeHtml(task.id)}" role="button" tabindex="0">
      <div class="${compact ? 'recent-task-title' : 'task-card-title'}">${title}</div>
      <div class="${compact ? 'recent-task-meta' : 'task-card-bottom'}"><span class="status-badge ${escapeHtml(task.state)}">${label}</span><span class="task-date">${escapeHtml(formatDate(task.updated_at))}</span></div>
    </div>`;
  }

  async function loadTasks(showToastOnError = false) {
    try {
      const data = await api('/api/tasks?limit=80');
      state.tasks = data.tasks || [];
      renderTaskLists();
      if (state.currentView === 'tasks' && state.selectedTaskId) {
        const selected = state.tasks.find(item => item.id === state.selectedTaskId);
        if (selected) await loadTaskDetail(selected.id, false);
      }
      schedulePolling();
    } catch (error) {
      if (showToastOnError) toast(error.message, true);
    }
  }

  function renderTaskLists() {
    const activeCount = state.tasks.filter(item => !['completed', 'failed', 'cancelled'].includes(item.state)).length;
    setText('#navTaskCount', String(activeCount));
    const recent = state.tasks.slice(0, 4);
    $('#recentTasks').innerHTML = recent.length ? recent.map(task => taskCard(task, false, true)).join('') : '<div class="empty-state small-empty">Your task activity will appear here.</div>';
    const all = $('#allTasks');
    if (state.tasks.length) {
      setText('#taskListCount', `${state.tasks.length} task${state.tasks.length === 1 ? '' : 's'}`);
      all.innerHTML = state.tasks.map(task => taskCard(task, task.id === state.selectedTaskId, false)).join('');
    } else {
      setText('#taskListCount', '0 tasks');
      all.innerHTML = '<div class="empty-state">No tasks yet. Start one from the command center.</div>';
    }
    bindTaskCards();
  }

  function bindTaskCards() {
    $$('[data-task-id]').forEach(card => {
      if (card.dataset.bound === 'true') return;
      card.dataset.bound = 'true';
      const open = () => {
        state.selectedTaskId = card.dataset.taskId;
        switchView('tasks');
        loadTaskDetail(card.dataset.taskId).catch(error => toast(error.message, true));
        renderTaskLists();
      };
      card.addEventListener('click', open);
      card.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); } });
    });
  }

  function planParts(plan) {
    if (Array.isArray(plan)) return { summary: '', steps: plan.map(String) };
    if (plan && typeof plan === 'object') return { summary: String(plan.summary || ''), steps: Array.isArray(plan.steps) ? plan.steps.map(String) : [] };
    return { summary: '', steps: [] };
  }

  async function loadTaskDetail(taskId, render = true) {
    if (!taskId) return;
    const task = await api(`/api/tasks/${encodeURIComponent(taskId)}`);
    if (render) state.selectedTaskId = taskId;
    renderTaskDetail(task);
    if (state.currentView === 'tasks') renderTaskLists();
  }

  function renderTaskDetail(task) {
    const plan = planParts(task.plan);
    const pending = task.pending_approval;
    const terminal = ['completed', 'failed', 'cancelled'].includes(task.state);
    const canEditPlan = (task.state === 'paused' || pending?.kind === 'plan_review') && pending?.kind !== 'tool';
    let controls = '';
    if (['queued', 'planning', 'running'].includes(task.state)) {
      controls += '<button class="button button-soft" data-task-action="pause">Ⅱ Pause</button>';
    }
    if (task.state === 'paused') controls += '<button class="button button-primary" data-task-action="resume">▶ Resume</button>';
    if (!terminal) controls += '<button class="button button-outline" data-task-action="cancel">× Cancel</button>';

    const planContent = plan.steps.length
      ? `<div class="detail-block"><div class="detail-block-head"><span>Execution plan</span><span>${plan.steps.length} steps</span></div><div class="detail-block-body">${plan.summary ? `<p>${escapeHtml(plan.summary)}</p>` : ''}${plan.steps.map((step, i) => `<div class="plan-step"><span class="plan-number">${i + 1}</span><span>${escapeHtml(step)}</span></div>`).join('')}</div></div>`
      : '<div class="detail-block"><div class="detail-block-head">Execution plan</div><div class="detail-block-body">Plan will appear after the configured provider responds.</div></div>';
    const editor = canEditPlan && plan.steps.length
      ? `<div class="detail-block"><div class="detail-block-head"><span>Edit plan</span><span>One step per line</span></div><div class="detail-block-body"><label class="sr-only" for="planSummaryInput">Plan summary</label><input class="plan-editor" id="planSummaryInput" value="${escapeHtml(plan.summary)}" placeholder="Plan summary" style="min-height:0;margin-bottom:8px"><label class="sr-only" for="planStepsInput">Plan steps, one per line</label><textarea class="plan-editor" id="planStepsInput">${escapeHtml(plan.steps.join('\n'))}</textarea><div class="plan-tools"><button class="button button-outline" data-task-action="save-plan">Save revised plan</button></div></div></div>`
      : '';
    const approval = pending ? `<div class="approval-callout"><strong>${pending.kind === 'plan_review' ? 'Plan review required' : 'User approval required'}</strong><br>${escapeHtml(pending.summary || 'NOVA is paused until you decide.')}${pending.tool ? `<br><span>Tool: ${escapeHtml(pending.tool)}</span>` : ''}${pending.approval?.path ? `<br><span>Target: ${escapeHtml(pending.approval.path)}</span>` : ''}<div class="approval-actions"><button class="button button-primary" data-task-action="approve">${pending.kind === 'plan_review' ? 'Approve & execute' : 'Approve action'}</button><button class="button button-outline" data-task-action="deny">${pending.kind === 'plan_review' ? 'Decline plan' : 'Deny action'}</button></div></div>` : '';
    const result = task.result ? `<div class="detail-block"><div class="detail-block-head"><span>Reported result</span><span class="status-badge ${escapeHtml(task.verification || 'unverified')}">${escapeHtml(task.verification || 'unverified')}</span></div><div class="detail-block-body"><div class="result-box">${escapeHtml(task.result)}</div><div class="verification-note ${escapeHtml(task.verification || 'unverified')}"><span class="verify-icon">${task.verification === 'verified' ? '✓' : '!'}</span><span>${escapeHtml(task.verification_note || 'No independent verification note.')}</span></div></div></div>` : '';
    const modelActivity = Array.isArray(task.models_used) ? task.models_used.slice(-20) : [];
    const modelUsage = modelActivity.length ? `<div class="detail-block"><div class="detail-block-head"><span>Actual model usage</span><span>${Number(task.request_count || 0)} provider request(s)</span></div><div class="detail-block-body">Mode requested: ${escapeHtml(modeLabel(task.intelligence_mode))}${modelActivity.map(item => `<div class="timeline-item"><span class="timeline-dot">${item.status === 'ok' ? '✓' : '!'}</span><div class="timeline-copy">${escapeHtml(item.role || 'model call')} · ${escapeHtml(item.name || item.model_id || 'model')} · ${escapeHtml(item.status || 'unknown')}<small>${escapeHtml(item.provider_type || '')} · ${item.latency_ms == null ? 'latency n/a' : `${Math.round(Number(item.latency_ms))} ms`} · ${tokenUsageLabel(item.total_tokens, item.usage_reported)}${item.estimated_cost_usd == null ? ' · cost unknown' : ` · est. $${Number(item.estimated_cost_usd).toFixed(6)}`}${item.error ? ` · ${escapeHtml(item.error)}` : ''}${item.retry_after_seconds != null ? ` · retry after ${Number(item.retry_after_seconds).toFixed(1)}s` : ''}</small></div></div>`).join('')}</div></div>` : '';
    const error = task.error ? `<div class="approval-callout" style="border-color:#644148;color:#ffb9bd">${escapeHtml(task.error)}</div>` : '';
    const events = (task.events || []).slice(-40);
    const timeline = events.length ? `<div class="detail-block"><div class="detail-block-head"><span>Execution timeline</span><span>${events.length} events</span></div><div class="detail-block-body"><div class="timeline">${events.map(event => `<div class="timeline-item"><span class="timeline-dot">${event.kind === 'autonomy_decision' ? '◉' : event.kind === 'tool_result' ? '↳' : event.kind === 'error' ? '!' : '·'}</span><div class="timeline-copy">${escapeHtml(event.message)}<small>${escapeHtml(formatDate(event.created_at))} · ${escapeHtml(event.kind)}</small></div></div>`).join('')}</div></div></div>` : '';

    $('#taskDetail').innerHTML = `<div class="task-detail-content">
      <div class="detail-topline"><span class="status-badge ${escapeHtml(task.state)}">${escapeHtml(friendlyState(task.state))}</span><div class="detail-controls">${controls}</div></div>
      <h2 class="detail-title">${escapeHtml(task.objective)}</h2><div class="detail-timestamps">Created ${escapeHtml(formatDate(task.created_at))} · Updated ${escapeHtml(formatDate(task.updated_at))} · ${escapeHtml(autonomyLevelLabel(task.autonomy_level))} · ${task.request_count || 0} AI requests · ${task.tool_call_count || 0} tool calls · ${tokenUsageLabel(task.token_usage, task.usage_complete)}</div>
      ${approval}${error}${planContent}${editor}${result}${modelUsage}${timeline}
    </div>`;
    bindTaskActions(task);
  }

  function bindTaskActions(task) {
    $$('[data-task-action]', $('#taskDetail')).forEach(button => {
      button.addEventListener('click', async () => {
        const action = button.dataset.taskAction;
        button.disabled = true;
        try {
          if (action === 'pause' || action === 'resume' || action === 'cancel') {
            await api(`/api/tasks/${encodeURIComponent(task.id)}/${action}`, { method: 'POST' });
            toast(action === 'cancel' ? 'Cancellation requested.' : `Task ${action} requested.`);
          } else if (action === 'approve' || action === 'deny') {
            await api(`/api/tasks/${encodeURIComponent(task.id)}/approve`, { method: 'POST', body: JSON.stringify({ approved: action === 'approve' }) });
            toast(action === 'approve' ? 'Approval recorded.' : 'Decision recorded.');
          } else if (action === 'save-plan') {
            const summary = $('#planSummaryInput').value.trim() || 'User-reviewed plan';
            const steps = $('#planStepsInput').value.split('\n').map(line => line.replace(/^\s*\d+[.)]\s*/, '').trim()).filter(Boolean);
            if (!steps.length) throw new Error('Keep at least one non-empty plan step.');
            await api(`/api/tasks/${encodeURIComponent(task.id)}/plan`, { method: 'PUT', body: JSON.stringify({ summary, steps }) });
            toast('Revised plan saved.');
          }
          await loadTasks();
          await loadTaskDetail(task.id);
        } catch (error) {
          toast(error.message, true);
        } finally {
          button.disabled = false;
        }
      });
    });
  }

  async function loadTools() {
    const data = await api('/api/tools');
    const tools = data.tools || [];
    const icons = { utility: '∑', files: '▧', research: '⌕' };
    $('#toolGrid').innerHTML = tools.map(tool => `<article class="tool-card"><div class="tool-card-top"><span class="tool-icon">${escapeHtml(icons[tool.category] || '⌘')}</span><span class="tool-availability ${tool.available ? '' : 'optional'}">${tool.available ? 'AVAILABLE' : 'NOT CONFIGURED'}</span></div><div class="tool-name">${escapeHtml(tool.name)}</div><div class="tool-description">${escapeHtml(tool.description)}</div><div class="tool-permission">Scope: ${escapeHtml(tool.permission)}<br>Autonomy class: ${escapeHtml(tool.autonomy_class || 'approval required')}${tool.available ? '' : `<br>${escapeHtml(tool.unavailable_reason || '')}`}</div></article>`).join('') || '<div class="empty-state">No tools are registered.</div>';
    const search = tools.find(tool => tool.name === 'research.search_web');
    if (search) {
      $('#researchState').textContent = search.available ? 'READY' : 'OPTIONAL';
      $('#researchDot').classList.toggle('available', search.available);
      $('#researchDot').classList.toggle('muted', !search.available);
    }
  }

  function currentMode() {
    return $('#intelligenceMode')?.value || state.defaultMode || 'balanced';
  }

  function modeLabel(value) {
    const found = state.modes.find(mode => mode.id === value);
    if (found) return found.label;
    return ({ fast: 'Fast', balanced: 'Balanced', frontier_fusion: 'Frontier Fusion', maximum_intelligence: 'Maximum Intelligence' })[value] || String(value || 'Balanced').replaceAll('_', ' ');
  }

  function autonomyLevelLabel(value) {
    return ({ assisted: 'A · Assisted', routine: 'B · Routine autonomy', advanced: 'C · Advanced (bounded)', high: 'D · High (bounded)' })[value] || 'Autonomy level unknown';
  }

  function tokenUsageLabel(tokens, complete) {
    const count = Number(tokens || 0).toLocaleString();
    if (complete) return `${count} provider-reported tokens`;
    return Number(tokens || 0) > 0 ? `${count} tokens reported; usage incomplete` : 'token usage unavailable';
  }

  function setCurrentMode(value) {
    const valid = state.modes.some(mode => mode.id === value) || ['fast', 'balanced', 'frontier_fusion', 'maximum_intelligence'].includes(value);
    const mode = valid ? value : (state.defaultMode || 'balanced');
    const select = $('#intelligenceMode');
    if (select) select.value = mode;
    try { localStorage.setItem('novaIntelligenceMode', mode); } catch (_error) {}
    renderModeCards();
  }

  async function loadModelDashboard() {
    const [modelsData, providersData, modesData, evalData] = await Promise.all([
      api('/api/models'), api('/api/models/providers'), api('/api/intelligence/modes'), api('/api/models/evaluations?limit=20'),
    ]);
    state.models = modelsData.models || [];
    state.providers = providersData.providers || [];
    state.modes = modesData.modes || [];
    state.modelLimits = modesData.limits || state.modelLimits;
    state.defaultMode = modesData.default_mode || 'balanced';
    const modelIds = new Set(state.models.filter(model => model.available).map(model => model.id));
    state.selectedModelIds = state.selectedModelIds.filter(id => modelIds.has(id)).slice(0, Number(state.modelLimits.max_models_per_fusion || 3));
    try { localStorage.setItem('novaSelectedModelIds', JSON.stringify(state.selectedModelIds)); } catch (_error) {}
    populateProviderSelect();
    const savedMode = (() => { try { return localStorage.getItem('novaIntelligenceMode'); } catch (_error) { return null; } })();
    setCurrentMode(savedMode || state.defaultMode);
    renderModelDashboard(evalData.evaluations || []);
  }

  function populateProviderSelect() {
    const select = $('#modelProviderType');
    if (!select) return;
    const current = select.value;
    select.innerHTML = state.providers.map(provider => `<option value="${escapeHtml(provider.id)}" data-base-url="${escapeHtml(provider.default_base_url)}" data-key-env="${escapeHtml(provider.key_env_default)}">${escapeHtml(provider.label)}</option>`).join('');
    if (state.providers.some(provider => provider.id === current)) select.value = current;
    if (!state.editingModelId) applyProviderDefaults();
  }

  function applyProviderDefaults() {
    const select = $('#modelProviderType');
    const provider = state.providers.find(item => item.id === select?.value) || state.providers[0];
    if (!provider || state.editingModelId) return;
    $('#modelBaseUrl').value = provider.default_base_url || '';
    $('#modelKeyEnv').value = provider.key_env_default || '';
    if (!$('#modelNameInput').value.trim()) $('#modelNameInput').value = `${provider.label} profile`;
  }

  function renderModelDashboard(evaluations = []) {
    const available = state.models.filter(item => item.available).length;
    const configured = state.models.filter(item => item.configured).length;
    const connected = state.models.filter(item => item.connected).length;
    const tested = state.models.filter(item => item.tested).length;
    $('#modelSummary').innerHTML = [
      ['Profiles', state.models.length, 'Environment + managed profiles'],
      ['Configured', configured, 'Credential reference is present'],
      ['Connected', connected, 'Recent catalog or inference response'],
      ['Inference-tested', tested, `${available} currently routable profile(s)`],
    ].map(([label, value, note]) => `<div class="summary-tile"><strong>${escapeHtml(value)}</strong><small>${escapeHtml(label)} · ${escapeHtml(note)}</small></div>`).join('');
    setText('#modelListSubtitle', `${available} available · ${state.selectedModelIds.length ? `${state.selectedModelIds.length} manually selected` : 'adaptive routing'}`);
    renderModeCards();
    renderModelCards();
    renderEvaluationHistory(evaluations);
  }

  function renderModeCards() {
    const target = $('#modeCards');
    if (!target) return;
    const selected = currentMode();
    const detail = {
      fast: 'One model, favor recent low latency. Reduced cross-checking.',
      balanced: 'One primary model; default. One available fallback if the primary fails.',
      frontier_fusion: 'Parallel analyses → disagreement review → synthesis. No majority vote.',
      maximum_intelligence: 'Fusion plus a critique and revision. More calls, latency, and cost.',
    };
    target.innerHTML = state.modes.map(mode => `<button type="button" class="mode-card${mode.id === selected ? ' selected' : ''}" data-mode-choice="${escapeHtml(mode.id)}"><span class="mode-cost">${mode.id === 'balanced' ? 'DEFAULT' : mode.id === 'maximum_intelligence' ? 'UP TO 7 CALLS' : mode.id === 'frontier_fusion' ? 'BOUNDED' : 'LOW LATENCY'}</span><strong>${escapeHtml(mode.label)}</strong><p>${escapeHtml(detail[mode.id] || mode.description)}</p></button>`).join('');
  }

  function modelStatusLabel(model) {
    return ({
      tested: 'Inference tested', connected: 'Connected', configured_unverified: 'Configured · untested',
      missing_credential: 'Missing credential', invalid_endpoint: 'Invalid endpoint', not_listed: 'Not in last catalog',
      test_failed: 'Inference test failed', catalog_listed: 'Listed · test chat', catalog_incomplete: 'Catalog incomplete', disabled: 'Disabled',
    })[model.status] || String(model.status || 'unknown').replaceAll('_', ' ');
  }

  function renderModelCards() {
    const target = $('#modelCards');
    if (!target) return;
    const max = Number(state.modelLimits.max_models_per_fusion || 3);
    if (!state.models.length) { target.innerHTML = '<div class="empty-state">No profiles are available.</div>'; return; }
    target.innerHTML = state.models.map(model => {
      const selected = state.selectedModelIds.includes(model.id);
      const checkedDisabled = !model.available || (!selected && state.selectedModelIds.length >= max);
      const stateClass = model.available ? (model.tested ? 'good' : 'warn') : (model.configured ? 'warn' : 'bad');
      const costs = model.input_cost_per_million == null || model.output_cost_per_million == null
        ? 'Rates not configured · cost unknown'
        : `Input $${Number(model.input_cost_per_million).toPrecision(4)} / Output $${Number(model.output_cost_per_million).toPrecision(4)} per 1M tokens`;
      const toolEvalLabel = model.tools_validated ? 'passed' : (model.tools_test_status === 'failed' ? 'failed' : 'not validated');
      const actions = [
        `<button class="button button-outline" data-model-action="test" data-model-id="${escapeHtml(model.id)}">Test · may bill</button>`,
        `<button class="button button-outline" data-model-action="catalog" data-model-id="${escapeHtml(model.id)}">Refresh catalog</button>`,
        `<button class="button button-outline" data-model-action="evaluate" data-model-id="${escapeHtml(model.id)}">Run eval · may bill</button>`,
        model.is_default ? '' : `<button class="button button-outline" data-model-action="default" data-model-id="${escapeHtml(model.id)}">Make primary</button>`,
        model.managed ? `<button class="button button-outline" data-model-action="edit" data-model-id="${escapeHtml(model.id)}">Edit</button><button class="button button-outline" data-model-action="toggle" data-enabled="${model.enabled ? 'false' : 'true'}" data-model-id="${escapeHtml(model.id)}">${model.enabled ? 'Disable' : 'Enable'}</button><button class="button button-outline" data-model-action="delete" data-model-id="${escapeHtml(model.id)}">Delete</button>` : '',
      ].filter(Boolean).join('');
      return `<article class="model-card"><div class="model-card-top"><input class="model-select-check" type="checkbox" data-model-select="${escapeHtml(model.id)}" aria-label="Select ${escapeHtml(model.name)} for manual routing" ${selected ? 'checked' : ''} ${checkedDisabled ? 'disabled' : ''}><div class="model-card-main"><div class="model-title-row"><strong>${escapeHtml(model.name)}</strong><span class="model-state ${stateClass}">${escapeHtml(modelStatusLabel(model))}</span>${model.is_default ? '<span class="default-mark">PRIMARY</span>' : ''}</div><div class="model-subtitle">${escapeHtml(model.provider_label)} · ${escapeHtml(model.model_id)}</div></div></div><div class="model-details"><span>Credential: ${escapeHtml(model.api_key_env)} · ${model.credential_configured ? 'set' : 'missing'}</span><span>Catalog: ${escapeHtml(model.availability_status || 'unknown')}${model.availability_checked_at ? ` · ${escapeHtml(formatDate(model.availability_checked_at))}` : ''}</span><span>Capabilities: ${escapeHtml((model.capabilities || []).join(', '))} · tool-call eval ${escapeHtml(toolEvalLabel)}</span><span>${escapeHtml(costs)}</span><span>${model.last_latency_ms == null ? 'Latency unmeasured' : `${Math.round(Number(model.last_latency_ms))} ms observed`} · ${Number(model.calls_success || 0)}/${Number(model.calls_total || 0)} successful calls</span></div><div class="model-actions">${actions}</div>${model.last_error ? `<div class="model-error">Last error: ${escapeHtml(model.last_error)}</div>` : ''}</article>`;
    }).join('');
  }

  function renderEvaluationHistory(evaluations) {
    const target = $('#evaluationHistory');
    if (!target) return;
    if (!evaluations.length) { target.innerHTML = '<div class="empty-state small-empty">No evaluation runs yet. Run a small suite from a model card.</div>'; return; }
    target.innerHTML = evaluations.map(run => {
      const model = state.models.find(item => item.id === run.model_id);
      return `<div class="evaluation-item"><div><strong>${escapeHtml(model?.name || run.model_id)}</strong><small>${escapeHtml(run.suite_version)} · ${escapeHtml(formatDate(run.created_at))} · ${Number(run.provider_requests || 0)} provider calls · ${tokenUsageLabel(run.total_tokens, run.results?.usage_complete)}${run.estimated_cost_usd == null ? ' · cost unknown' : ` · est. $${Number(run.estimated_cost_usd).toFixed(6)}`}</small></div><span class="status-badge ${escapeHtml(run.status)}">${escapeHtml(run.status)} · ${Number(run.results?.score || 0)}%</span></div>`;
    }).join('');
  }

  function beginModelEdit(model) {
    if (!model || !model.managed) return;
    state.editingModelId = model.id;
    $('#modelFormTitle').textContent = `Edit ${model.name}`;
    $('#modelProviderType').value = model.provider_type;
    $('#modelProviderType').disabled = true;
    $('#modelNameInput').value = model.name;
    $('#modelIdInput').value = model.model_id;
    $('#modelBaseUrl').value = model.base_url;
    $('#modelKeyEnv').value = model.api_key_env;
    $('#capabilityTools').checked = (model.capabilities || []).includes('tools');
    $('#modelContextWindow').value = model.context_window || '';
    $('#modelPriority').value = model.priority ?? 50;
    $('#modelInputCost').value = model.input_cost_per_million ?? '';
    $('#modelOutputCost').value = model.output_cost_per_million ?? '';
    $('#modelEnabled').checked = Boolean(model.enabled);
    $('#modelIsDefault').checked = Boolean(model.is_default);
    $('#saveModelButton').textContent = 'Save changes';
    $('#cancelModelEdit').hidden = false;
    $('#modelFormError').textContent = '';
    $('#modelProfileForm').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function clearModelEdit() {
    state.editingModelId = null;
    $('#modelProfileForm').reset();
    $('#modelProviderType').disabled = false;
    $('#modelFormTitle').textContent = 'Add a provider profile';
    $('#saveModelButton').textContent = 'Save model profile';
    $('#cancelModelEdit').hidden = true;
    $('#capabilityChat').checked = true;
    $('#capabilityTools').checked = false;
    $('#modelEnabled').checked = true;
    $('#modelPriority').value = '50';
    $('#modelFormError').textContent = '';
    applyProviderDefaults();
  }

  async function saveModelProfile(event) {
    event.preventDefault();
    const errorNode = $('#modelFormError');
    errorNode.textContent = '';
    const parseOptional = selector => {
      const value = $(selector).value.trim();
      return value === '' ? null : Number(value);
    };
    const payload = {
      name: $('#modelNameInput').value.trim(),
      provider_type: $('#modelProviderType').value,
      model_id: $('#modelIdInput').value.trim(),
      base_url: $('#modelBaseUrl').value.trim(),
      api_key_env: $('#modelKeyEnv').value.trim(),
      capabilities: ['chat', ...($('#capabilityTools').checked ? ['tools'] : [])],
      context_window: parseOptional('#modelContextWindow') ?? 0,
      priority: parseOptional('#modelPriority') ?? 50,
      input_cost_per_million: parseOptional('#modelInputCost'),
      output_cost_per_million: parseOptional('#modelOutputCost'),
      enabled: $('#modelEnabled').checked,
      is_default: $('#modelIsDefault').checked,
    };
    const button = $('#saveModelButton');
    button.disabled = true;
    try {
      const editingId = state.editingModelId;
      const data = await api(editingId ? `/api/models/${encodeURIComponent(editingId)}` : '/api/models', {
        method: editingId ? 'PUT' : 'POST', body: JSON.stringify(payload),
      });
      toast(editingId ? 'Model profile updated. Run a connection test before relying on it.' : 'Model profile saved. Add its server-side credential and refresh the catalog.');
      clearModelEdit();
      await loadModelDashboard();
    } catch (error) {
      errorNode.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  }

  async function loadProviderCatalog(profileId) {
    state.catalogProfileId = profileId;
    const panel = $('#modelCatalogPanel');
    panel.hidden = false;
    $('#modelCatalogList').innerHTML = '<div class="empty-state">Checking the provider model catalog…</div>';
    try {
      const data = await api(`/api/models/${encodeURIComponent(profileId)}/catalog`);
      const model = state.models.find(item => item.id === profileId);
      const subtitle = data.availability_status === 'not_listed'
        ? `Configured identifier ${data.configured_model_id || ''} was not found in the complete provider catalog. Choose a listed ID, then save.`
        : data.availability_status === 'catalog_incomplete'
          ? 'The catalog is paginated beyond NOVA’s bounded first page; this identifier was not confirmed. Run a small inference test or choose a listed ID.'
          : `Catalog response received${data.checked_at ? ` · ${formatDate(data.checked_at)}` : ''}. Account entitlement may still vary.`;
      setText('#catalogSubtitle', subtitle);
      const rows = (data.models || []).slice(0, 300);
      $('#modelCatalogList').innerHTML = rows.map(item => `<button type="button" class="catalog-model" data-catalog-model="${escapeHtml(item.id)}" data-display-name="${escapeHtml(item.display_name || item.id)}"><strong>${escapeHtml(item.display_name || item.id)}</strong><small>${escapeHtml(item.id)}${item.capabilities?.length ? ` · ${escapeHtml(item.capabilities.join(', '))}` : ''}</small></button>`).join('') || '<div class="empty-state">No models were returned by this provider catalog.</div>';
      if (model && data.availability_status === 'available') toast('Configured model identifier appears in the current provider catalog.');
      await loadModelDashboard();
      // Keep the catalog panel open after refreshing the registry.
      panel.hidden = false;
    } catch (error) {
      $('#modelCatalogList').textContent = error.message;
      setText('#catalogSubtitle', 'Catalog check failed; no model availability was confirmed.');
      panel.hidden = false;
    }
  }

  function useCatalogModel(modelId, displayName) {
    const source = state.models.find(item => item.id === state.catalogProfileId);
    clearModelEdit();
    if (source) {
      $('#modelProviderType').value = source.provider_type;
      $('#modelBaseUrl').value = source.base_url;
      $('#modelKeyEnv').value = source.api_key_env;
      $('#modelNameInput').value = `${source.provider_label} · ${displayName}`.slice(0, 100);
      $('#modelEnabled').checked = true;
    }
    $('#modelIdInput').value = modelId;
    $('#modelProfileForm').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    toast('Model identifier copied into the profile form. Save to apply it.');
  }

  async function handleModelAction(event) {
    const button = event.target.closest('[data-model-action]');
    if (!button) return;
    const profileId = button.dataset.modelId;
    const action = button.dataset.modelAction;
    button.disabled = true;
    try {
      if (action === 'test') {
        const result = await api(`/api/models/${encodeURIComponent(profileId)}/test`, { method: 'POST' });
        toast(`Inference check succeeded in ${Math.round(result.latency_ms || 0)} ms${result.estimated_cost_usd == null ? ' · cost unknown' : ` · est. $${Number(result.estimated_cost_usd).toFixed(6)}`}.`);
      } else if (action === 'catalog') {
        await loadProviderCatalog(profileId);
      } else if (action === 'evaluate') {
        if (!window.confirm('Run the small NOVA evaluation suite? It sends up to three provider requests and may incur charges.')) return;
        const result = await api(`/api/models/${encodeURIComponent(profileId)}/evaluate`, { method: 'POST' });
        toast(`Evaluation: ${result.score}% · ${result.provider_requests} provider calls${result.estimated_cost_usd == null ? ' · cost unknown' : ` · est. $${Number(result.estimated_cost_usd).toFixed(6)}`}.`);
      } else if (action === 'default') {
        await api(`/api/models/${encodeURIComponent(profileId)}/default`, { method: 'POST' });
        toast('Primary model updated.');
      } else if (action === 'edit') {
        beginModelEdit(state.models.find(item => item.id === profileId));
        return;
      } else if (action === 'toggle') {
        await api(`/api/models/${encodeURIComponent(profileId)}`, { method: 'PUT', body: JSON.stringify({ enabled: button.dataset.enabled === 'true' }) });
        toast(button.dataset.enabled === 'true' ? 'Model enabled.' : 'Model disabled.');
      } else if (action === 'delete') {
        if (!window.confirm('Delete this model profile? Its recorded run/evaluation history will remain.')) return;
        await api(`/api/models/${encodeURIComponent(profileId)}`, { method: 'DELETE' });
        state.selectedModelIds = state.selectedModelIds.filter(id => id !== profileId);
        toast('Model profile deleted.');
      }
      await loadModelDashboard();
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  function renderIntelligenceMetadata(article, intelligence) {
    if (!article || !intelligence || !Object.keys(intelligence).length) return;
    const body = $('.message-body', article);
    const box = document.createElement('div');
    box.className = 'run-metadata';
    const models = Array.isArray(intelligence.models) ? intelligence.models : [];
    const successful = models.filter(model => model.status === 'ok');
    const cost = intelligence.estimated_cost_usd == null ? 'cost estimate unavailable' : `estimated $${Number(intelligence.estimated_cost_usd).toFixed(6)}`;
    const names = [...new Set(successful.map(model => model.name || model.model_id).filter(Boolean))];
    const line = document.createElement('div');
    line.className = 'run-meta-line';
    line.textContent = `${modeLabel(intelligence.mode_effective)}${intelligence.mode_effective !== intelligence.mode_requested ? ` · requested ${modeLabel(intelligence.mode_requested)}` : ''} · ${Number(intelligence.provider_requests || 0)} provider request(s) · ${tokenUsageLabel(intelligence.total_tokens, intelligence.usage_complete)} · ${cost}${names.length ? ` · ${names.join(', ')}` : ''}`;
    box.appendChild(line);
    if (intelligence.degraded_reason) {
      const warning = document.createElement('div');
      warning.className = 'run-meta-warning';
      warning.textContent = `Mode reduced: ${intelligence.degraded_reason}`;
      box.appendChild(warning);
    }
    if (Array.isArray(intelligence.warnings) && intelligence.warnings.length) {
      const warning = document.createElement('div');
      warning.className = 'run-meta-warning';
      warning.textContent = intelligence.warnings.join(' ');
      box.appendChild(warning);
    }
    const comparisons = Array.isArray(intelligence.model_results) ? intelligence.model_results : [];
    if (comparisons.length) {
      const details = document.createElement('details');
      details.className = 'run-model-details';
      const summary = document.createElement('summary');
      summary.textContent = `Inspect model comparison (${comparisons.length} model call(s))`;
      details.appendChild(summary);
      for (const result of comparisons) {
        const item = document.createElement('div');
        item.className = 'run-model-item';
        item.textContent = `${result.name || result.model_id || 'Model'} · ${String(result.role || 'analysis').replaceAll('_', ' ')} · ${result.status || 'unknown'}\n${result.summary || 'No summary returned.'}`;
        details.appendChild(item);
      }
      box.appendChild(details);
    }
    const checkText = Array.isArray(intelligence.checks_performed) ? intelligence.checks_performed.join(' · ') : '';
    if (checkText) {
      const note = document.createElement('div');
      note.className = 'run-model-item';
      note.textContent = `Checks: ${checkText}`;
      box.appendChild(note);
    }
    if (intelligence.run_id) {
      const actions = document.createElement('div');
      actions.className = 'feedback-actions';
      const label = document.createElement('span');
      label.textContent = 'Helpful?';
      actions.append(label);
      for (const [rating, text] of [[5, '👍'], [1, '👎']]) {
        const button = document.createElement('button');
        button.type = 'button'; button.className = 'feedback-button'; button.textContent = text;
        button.setAttribute('aria-label', rating === 5 ? 'Mark this response helpful' : 'Mark this response not helpful');
        button.addEventListener('click', async () => {
          button.disabled = true;
          try {
            await api('/api/intelligence/feedback', { method: 'POST', body: JSON.stringify({ run_id: intelligence.run_id, rating }) });
            label.textContent = 'Feedback saved';
          } catch (error) { toast(error.message, true); button.disabled = false; }
        });
        actions.appendChild(button);
      }
      box.appendChild(actions);
    }
    body.appendChild(box);
    $('#chatLog').scrollTop = $('#chatLog').scrollHeight;
  }

  async function loadHealth() {
    const health = await api('/api/health');
    state.health = health;
    const configured = Boolean(health.provider_configured);
    const available = Number(health.available_models || 0) > 0;
    const storageHealthy = health.storage_healthy !== false;
    $('#connectionDot').classList.toggle('online', storageHealthy && available);
    setText('#connectionLabel', !storageHealthy ? 'Storage issue' : (available ? 'System ready · model available' : (configured ? 'Provider configured · test a model' : 'Provider setup required')));
    setText('#modelName', configured ? (health.model || `${health.configured_models || 1} configured model profile(s)`) : 'AI provider not configured');
    setText('#modelHost', configured ? `${health.provider_host || 'Provider profiles'} · server-side` : 'Set a server-side provider key');
    setText('#providerStatus', available ? 'AVAILABLE' : (configured ? 'UNTESTED' : 'NOT SET'));
    $('#providerLed').classList.toggle('active', available);
    $('#providerLed').classList.toggle('warning', !available);
    setText('#searchStatus', health.web_search_configured ? 'CONFIGURED' : 'OPTIONAL');
    $('#searchLed').classList.toggle('active', Boolean(health.web_search_configured));
    setText('#settingsModel', configured ? (health.model || `${health.configured_models || 1} model profile(s) configured`) : 'Not connected');
    setText('#settingsProviderHost', configured ? (health.provider_host || 'Server-side registry') : '—');
    $('#settingsProviderPill').textContent = configured ? 'CONFIGURED' : 'NOT CONFIGURED';
    $('#settingsProviderPill').classList.toggle('good', configured);
    setText('#authModeText', health.authentication_required ? 'Access token + HttpOnly session cookie' : 'No access token configured');
    setText('#authModeBadge', health.authentication_required ? 'PROTECTED' : 'OPEN');
    setText('#footerCloud', `${health.provider_configured ? 'Cloud inference configured' : 'AI provider not configured'} · workspace sandbox`);
    // Take the version from the server so the footer cannot drift from
    // nova.__version__; keep the static HTML value if the API omits it.
    if (health.version) setText('#footerVersion', health.version);
    document.body.classList.toggle('low-resource', Boolean(health.low_resource_mode));
    $('#lowResourceDot').style.background = health.low_resource_mode ? 'var(--teal)' : '#e9b960';
    $('#lowResourceDot').style.boxShadow = health.low_resource_mode ? '0 0 9px rgba(101,219,200,.4)' : 'none';
    const resourceCaption = $('.resource-card small');
    if (resourceCaption) resourceCaption.textContent = health.low_resource_mode ? 'Single worker · quieter polling' : 'Configured concurrency · active polling';
    if (health.web_search_configured) {
      $('#researchState').textContent = 'READY';
      $('#researchDot').classList.add('available');
      $('#researchDot').classList.remove('muted');
    }
  }

  async function loadUsage() {
    const data = await api('/api/usage');
    const observedTokens = Number(data.observed_tokens || 0);
    const usageComplete = Boolean(data.usage_reported_complete);
    const hasRequests = Number(data.observed_ai_requests || 0) > 0;
    const usageNote = !hasRequests ? 'No provider usage yet' : (usageComplete ? 'Provider-reported · cost may be unknown' : 'Partial/incomplete provider usage data');
    setText('#tokenCount', observedTokens.toLocaleString());
    setText('#settingsTokens', `${observedTokens.toLocaleString()} tokens · ${usageComplete ? 'complete' : hasRequests ? 'incomplete' : 'no usage'}`);
    const usageCaption = $('.model-usage small');
    if (usageCaption) usageCaption.textContent = usageNote;
    const limits = data.limits || {};
    const node = $('#limitsList .setting-row:nth-child(2) .setting-value');
    if (node) node.textContent = `${limits.max_task_steps ?? '—'} steps · ${limits.max_ai_requests_per_task ?? '—'} req/task · ${limits.max_ai_requests_per_minute ?? '—'}/min · ${limits.max_task_seconds ?? '—'}s · ${limits.max_parallel_tasks ?? '—'} worker`;
  }

  async function loadGoals() {
    const data = await api('/api/goals');
    state.goals = data.goals || [];
    const scheduler = data.scheduler || {};
    const cap = Number(scheduler.daily_run_cap || 0);
    const status = scheduler.enabled
      ? `In-process scheduler ${scheduler.status === 'in_process' ? 'running' : 'configured'} · cap ${cap} scheduled run(s)/UTC day · polls every ${scheduler.poll_seconds || '—'}s. ${scheduler.execution || ''}`
      : `Automatic schedules are disabled · daily cap ${cap}. “Run now” remains available; configure NOVA_GOAL_SCHEDULER_ENABLED and a nonzero daily cap to enable schedules.`;
    setText('#goalSchedulerNotice', status);
    const list = $('#goalList');
    setText('#goalListCount', `${state.goals.length} goal${state.goals.length === 1 ? '' : 's'}`);
    if (!state.goals.length) {
      list.innerHTML = '<div class="empty-state">No goals saved. Add one to define what proactive work is allowed.</div>';
      return;
    }
    list.innerHTML = state.goals.map(goal => {
      const enabled = Boolean(goal.enabled);
      const lastState = goal.last_task_state ? friendlyState(goal.last_task_state) : 'Not run yet';
      return `<article class="goal-card"><div class="goal-card-top"><div><h3>${escapeHtml(goal.name)}</h3><span class="goal-cadence">${escapeHtml(goal.cadence)} · ${enabled ? 'SCHEDULED' : 'PAUSED'}</span></div><span class="status-badge ${enabled ? 'completed' : 'paused'}">${enabled ? 'enabled' : 'disabled'}</span></div><p class="goal-objective">${escapeHtml(goal.objective)}</p><div class="goal-meta"><span>Next: ${escapeHtml(enabled ? formatDate(goal.next_run_at) : 'not scheduled')}</span><span>Last task: ${escapeHtml(lastState)}${goal.last_run_at ? ` · ${escapeHtml(formatDate(goal.last_run_at))}` : ''}</span></div><div class="goal-actions"><button class="button button-primary" data-goal-action="run" data-goal-id="${escapeHtml(goal.id)}">▶ Run now</button><button class="button button-outline" data-goal-action="edit" data-goal-id="${escapeHtml(goal.id)}">Edit</button><button class="button button-outline" data-goal-action="toggle" data-goal-id="${escapeHtml(goal.id)}" data-enabled="${enabled ? 'false' : 'true'}">${enabled ? 'Pause schedule' : 'Enable schedule'}</button>${goal.last_task_id ? `<button class="button button-outline" data-goal-action="task" data-goal-id="${escapeHtml(goal.id)}">View latest task</button>` : ''}</div></article>`;
    }).join('');
  }

  function clearGoalForm() {
    state.editingGoalId = null;
    $('#editingGoalId').value = '';
    $('#goalNameInput').value = '';
    $('#goalObjectiveInput').value = '';
    $('#goalInterval').value = '1440';
    $('#goalEnabledInput').checked = false;
    $('#goalFormTitle').textContent = 'Configure a goal';
    $('#saveGoalButton').textContent = 'Save goal';
    $('#cancelGoalEdit').hidden = true;
    $('#goalFormError').textContent = '';
  }

  async function saveGoal(event) {
    event.preventDefault();
    const button = $('#saveGoalButton');
    const errorNode = $('#goalFormError');
    errorNode.textContent = '';
    button.disabled = true;
    const payload = {
      name: $('#goalNameInput').value.trim(),
      objective: $('#goalObjectiveInput').value.trim(),
      interval_minutes: Number($('#goalInterval').value),
      enabled: $('#goalEnabledInput').checked,
    };
    try {
      const id = state.editingGoalId;
      if (id) {
        await api(`/api/goals/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(payload) });
        toast('Configured goal updated.');
      } else {
        await api('/api/goals', { method: 'POST', body: JSON.stringify(payload) });
        toast(payload.enabled ? 'Goal saved and scheduled.' : 'Goal saved. Its schedule is paused until enabled.');
      }
      clearGoalForm();
      await loadGoals();
    } catch (error) {
      errorNode.textContent = error.message;
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function handleGoalAction(event) {
    const button = event.target.closest('[data-goal-action]');
    if (!button) return;
    const goal = state.goals.find(item => item.id === button.dataset.goalId);
    if (!goal) return;
    const action = button.dataset.goalAction;
    button.disabled = true;
    try {
      if (action === 'edit') {
        state.editingGoalId = goal.id;
        $('#editingGoalId').value = goal.id;
        $('#goalNameInput').value = goal.name;
        $('#goalObjectiveInput').value = goal.objective;
        $('#goalInterval').value = String(goal.interval_minutes);
        $('#goalEnabledInput').checked = Boolean(goal.enabled);
        $('#goalFormTitle').textContent = 'Edit configured goal';
        $('#saveGoalButton').textContent = 'Update goal';
        $('#cancelGoalEdit').hidden = false;
        $('#goalFormError').textContent = '';
        $('#goalForm').scrollIntoView({ behavior: 'smooth', block: 'start' });
        $('#goalNameInput').focus();
        return;
      }
      if (action === 'toggle') {
        const enabled = button.dataset.enabled === 'true';
        await api(`/api/goals/${encodeURIComponent(goal.id)}`, { method: 'PUT', body: JSON.stringify({ enabled }) });
        toast(enabled ? 'Goal schedule enabled.' : 'Goal schedule paused.');
      } else if (action === 'run') {
        if (!window.confirm(`Run “${goal.name}” now? This may send bounded provider requests and perform routine registered tools under the current autonomy policy.`)) return;
        const result = await api(`/api/goals/${encodeURIComponent(goal.id)}/run`, { method: 'POST' });
        state.selectedTaskId = result.task.id;
        toast('Manual goal run queued. Its plan, actions, and evidence will appear in Tasks & plans.');
        await loadTasks(true);
        switchView('tasks');
        await loadTaskDetail(result.task.id);
      } else if (action === 'task' && goal.last_task_id) {
        state.selectedTaskId = goal.last_task_id;
        switchView('tasks');
        await loadTaskDetail(goal.last_task_id);
      }
      await loadGoals();
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function loadSetup() {
    const data = await api('/api/setup');
    const checks = data.checks || [];
    $('#setupChecklist').innerHTML = `${checks.map(check => `<div class="setup-row"><span class="setup-marker ${escapeHtml(check.status)}">${check.status === 'ready' ? '✓' : check.status === 'attention' ? '!' : '·'}</span><div><strong>${escapeHtml(check.label)}</strong><small>${escapeHtml(check.detail)}</small></div><span class="setup-state ${escapeHtml(check.status)}">${escapeHtml(check.status)}</span></div>`).join('')}${(data.next_steps || []).map(item => `<div class="setup-next-step">Next: ${escapeHtml(item)}</div>`).join('')}`;
  }

  async function runAutonomyBenchmark() {
    const button = $('#runAutonomyBenchmark');
    const target = $('#autonomyBenchmarkResult');
    button.disabled = true;
    target.textContent = 'Running isolated policy checks…';
    try {
      const data = await api('/api/autonomy/benchmark', { method: 'POST' });
      target.innerHTML = `<strong class="benchmark-${escapeHtml(data.status)}">${escapeHtml(data.passed)}/${escapeHtml(data.total)} checks ${escapeHtml(data.status)}</strong><small>${Number(data.duration_ms || 0).toFixed(1)} ms · ${Number(data.provider_requests || 0)} provider calls · temporary workspace only</small><ul>${(data.cases || []).map(item => `<li class="benchmark-${escapeHtml(item.status)}">${item.status === 'passed' ? '✓' : '!'} ${escapeHtml(item.id)} — ${escapeHtml(item.detail)}</li>`).join('')}</ul><small>${escapeHtml(data.limitations || '')}</small>`;
      if (data.status !== 'passed') toast('One or more autonomy policy checks failed.', true);
    } catch (error) {
      target.textContent = error.message;
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function loadAutonomyPolicy() {
    const data = await api('/api/autonomy');
    state.autonomyPolicy = data.policy || null;
    if (!state.autonomyPolicy) return;
    const policy = state.autonomyPolicy;
    $('#autonomyLevel').value = policy.level || 'routine';
    $('#autonomyOverrides').value = Object.entries(policy.tool_overrides || {}).map(([name, rule]) => `${name} = ${rule}`).join(String.fromCharCode(10));
    $('#autonomyScopes').value = (policy.authorized_overwrite_prefixes || []).join(String.fromCharCode(10));
    const letter = ({ assisted: 'A', routine: 'B', advanced: 'C', high: 'D' })[policy.level] || '?';
    setText('#autonomyStatePill', `LEVEL ${letter}`);
    setText('#autonomyLevelSummary', `${policy.levels?.find(item => item.id === policy.level)?.name || 'Routine autonomy'} · policy saved locally`);
    const overrides = Object.keys(policy.tool_overrides || {}).length;
    const scopes = (policy.authorized_overwrite_prefixes || []).length;
    setText('#autonomyNotice', `${policy.levels?.find(item => item.id === policy.level)?.description || ''} ${overrides} tool override(s); ${scopes} path-scoped overwrite grant(s). ${policy.notice || ''}`);
  }

  async function saveAutonomyPolicy(event) {
    event.preventDefault();
    const button = $('#saveAutonomyButton');
    const errorNode = $('#autonomyFormError');
    errorNode.textContent = '';
    button.disabled = true;
    try {
      const overrides = {};
      for (const line of $('#autonomyOverrides').value.split(String.fromCharCode(10))) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const match = trimmed.match(/^([a-z0-9_.-]+) *= *(allow|approve|deny)$/i);
        if (!match) throw new Error(`Invalid tool rule: ${trimmed}. Use tool.name = allow, approve, or deny.`);
        overrides[match[1]] = match[2].toLowerCase();
      }
      const scopes = $('#autonomyScopes').value.split(String.fromCharCode(10)).map(item => item.trim()).filter(Boolean);
      const data = await api('/api/autonomy', {
        method: 'PUT',
        body: JSON.stringify({ level: $('#autonomyLevel').value, tool_overrides: overrides, authorized_overwrite_prefixes: scopes }),
      });
      state.autonomyPolicy = data.policy;
      await loadAutonomyPolicy();
      toast('Autonomy policy saved. It applies to the next tool action.');
    } catch (error) {
      errorNode.textContent = error.message;
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function loadAll() {
    await Promise.allSettled([loadHealth(), loadTasks(), loadTools(), loadUsage(), loadConversation(), loadModelDashboard(), loadAutonomyPolicy(), loadGoals(), loadSetup()]);
    schedulePolling();
  }

  function schedulePolling() {
    if (state.pollTimer) window.clearTimeout(state.pollTimer);
    const active = state.tasks.some(item => !['completed', 'failed', 'cancelled'].includes(item.state));
    const lowResource = Boolean(state.health?.low_resource_mode);
    const delay = active ? (lowResource ? 9000 : 4000) : (lowResource ? 30000 : 15000);
    state.pollTimer = window.setTimeout(async () => {
      await Promise.allSettled([loadTasks(), loadUsage()]);
      if (state.currentView === 'settings') await loadHealth().catch(() => {});
      if (state.currentView === 'goals') await loadGoals().catch(() => {});
      schedulePolling();
    }, delay);
  }

  async function submitLogin(event) {
    event.preventDefault();
    const token = $('#authToken').value;
    $('#authError').textContent = '';
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || 'Sign in failed.');
      state.authenticated = true;
      closeAuth();
      setText('#authLabel', 'Protected session');
      $('#logoutButton').hidden = false;
      await loadAll();
      toast('Secure session started.');
    } catch (error) {
      $('#authError').textContent = error.message;
      $('#authToken').select();
    }
  }

  async function initialize() {
    renderTodayLabel();
    const storedTheme = localStorage.getItem('novaTheme');
    if (storedTheme === 'light') document.body.classList.add('light');
    $('#themeButton').addEventListener('click', () => {
      document.body.classList.toggle('light');
      localStorage.setItem('novaTheme', document.body.classList.contains('light') ? 'light' : 'dark');
    });
    $$('.nav-item').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
    $$('[data-view]:not(.nav-item)').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
    $('#mobileMenu').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
    document.addEventListener('click', event => {
      if (window.innerWidth <= 890 && $('#sidebar').classList.contains('open') && !$('#sidebar').contains(event.target) && !$('#mobileMenu').contains(event.target)) $('#sidebar').classList.remove('open');
    });
    $('#chatForm').addEventListener('submit', event => { event.preventDefault(); sendChat(); });
    $('#messageInput').addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); sendChat(); }
    });
    $('#runTaskButton').addEventListener('click', createTask);
    $('#intelligenceMode').addEventListener('change', event => setCurrentMode(event.target.value));
    $('#modeCards').addEventListener('click', event => {
      const choice = event.target.closest('[data-mode-choice]');
      if (choice) setCurrentMode(choice.dataset.modeChoice);
    });
    $('#modelProviderType').addEventListener('change', applyProviderDefaults);
    $('#modelProfileForm').addEventListener('submit', saveModelProfile);
    $('#autonomyForm').addEventListener('submit', saveAutonomyPolicy);
    $('#runAutonomyBenchmark').addEventListener('click', runAutonomyBenchmark);
    $('#goalForm').addEventListener('submit', saveGoal);
    $('#goalList').addEventListener('click', handleGoalAction);
    $('#cancelGoalEdit').addEventListener('click', clearGoalForm);
    $('#refreshGoals').addEventListener('click', () => loadGoals().catch(error => toast(error.message, true)));
    $('#refreshSetup').addEventListener('click', () => loadSetup().catch(error => toast(error.message, true)));
    $('#cancelModelEdit').addEventListener('click', clearModelEdit);
    $('#refreshModels').addEventListener('click', () => loadModelDashboard().catch(error => toast(error.message, true)));
    $('#refreshModelList').addEventListener('click', () => loadModelDashboard().catch(error => toast(error.message, true)));
    $('#modelCards').addEventListener('click', handleModelAction);
    $('#modelCards').addEventListener('change', event => {
      const checkbox = event.target.closest('[data-model-select]');
      if (!checkbox) return;
      const id = checkbox.dataset.modelSelect;
      if (checkbox.checked) {
        const max = Number(state.modelLimits.max_models_per_fusion || 3);
        if (state.selectedModelIds.length >= max) { checkbox.checked = false; toast(`Select no more than ${max} models.`, true); return; }
        if (!state.selectedModelIds.includes(id)) state.selectedModelIds.push(id);
      } else {
        state.selectedModelIds = state.selectedModelIds.filter(item => item !== id);
      }
      try { localStorage.setItem('novaSelectedModelIds', JSON.stringify(state.selectedModelIds)); } catch (_error) {}
      renderModelCards();
      setText('#modelListSubtitle', `${state.models.filter(item => item.available).length} available · ${state.selectedModelIds.length ? `${state.selectedModelIds.length} manually selected` : 'adaptive routing'}`);
    });
    $('#modelCatalogList').addEventListener('click', event => {
      const choice = event.target.closest('[data-catalog-model]');
      if (choice) useCatalogModel(choice.dataset.catalogModel, choice.dataset.displayName || choice.dataset.catalogModel);
    });
    $('#closeCatalog').addEventListener('click', () => { $('#modelCatalogPanel').hidden = true; });
    $('#newTaskButton').addEventListener('click', () => { switchView('command'); $('#messageInput').focus(); });
    $('#refreshTasks').addEventListener('click', () => loadTasks(true));
    $('#refreshStatus').addEventListener('click', async () => { await loadHealth(); await loadUsage(); toast('System status refreshed.'); });
    $('#emergencyButton').addEventListener('click', emergencyStop);
    $('#emergencySettingsButton').addEventListener('click', emergencyStop);
    $('#profileButton').addEventListener('click', () => switchView('settings'));
    $('#authForm').addEventListener('submit', submitLogin);
    $('#logoutButton').addEventListener('click', async () => {
      try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (_error) {}
      state.authenticated = false;
      showAuth('Signed out.');
    });
    $$('.prompt-chip').forEach(chip => chip.addEventListener('click', () => { $('#messageInput').value = chip.dataset.prompt; $('#messageInput').focus(); }));

    try {
      await loadHealth();
      const auth = await api('/api/auth/status');
      state.authRequired = Boolean(auth.required);
      state.authenticated = Boolean(auth.authenticated);
      if (state.authRequired && !state.authenticated) {
        $('#logoutButton').hidden = false;
        showAuth();
      } else {
        $('#logoutButton').hidden = !state.authRequired;
        setText('#authLabel', state.authRequired ? 'Protected session' : 'Local session');
        await loadAll();
      }
    } catch (error) {
      setText('#connectionLabel', 'Server unavailable');
      toast(error.message, true);
    }
  }

  async function emergencyStop() {
    if (!window.confirm('Cancel all active NOVA tasks? This will not undo work already completed.')) return;
    try {
      const data = await api('/api/tasks/emergency-stop', { method: 'POST' });
      toast(`${data.count || 0} active task(s) cancelled.`);
      await loadTasks(true);
      if (state.selectedTaskId) await loadTaskDetail(state.selectedTaskId).catch(() => {});
    } catch (error) {
      toast(error.message, true);
    }
  }

  document.addEventListener('DOMContentLoaded', initialize);
})();
