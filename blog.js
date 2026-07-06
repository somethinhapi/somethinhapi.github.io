/* ------------------------------------------------------------------
   Simple no-build blog engine.
   - Reads posts.json (newest first is recommended, but we also sort by date)
   - Renders a list, and renders individual posts from posts/<file> markdown.
   - Article view is opened via ?p=<slug> so links are shareable.
-------------------------------------------------------------------*/

async function loadPosts() {
  try {
    const res = await fetch('posts.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error('posts.json ' + res.status);
    const posts = await res.json();
    // sort newest first by date
    posts.sort((a, b) => (a.date < b.date ? 1 : -1));
    return posts;
  } catch (e) {
    console.error('无法加载 posts.json', e);
    return [];
  }
}

function fmtDate(iso) {
  // iso: "2026-07-02"
  const [y, m, d] = String(iso).split('-');
  if (!y) return iso;
  return `${y} 年 ${Number(m)} 月 ${Number(d)} 日`;
}

/* Render a post list into `container`. options: { limit, compact } */
async function renderPostList(container, options = {}) {
  if (!container) return;
  const posts = await loadPosts();
  const list = options.limit ? posts.slice(0, options.limit) : posts;

  if (!list.length) {
    container.innerHTML = '<p class="empty">还没有日志。第一篇正在路上 ✍️</p>';
    return;
  }

  // Compact mode (homepage): only the title + an "enter" button on the right.
  if (options.compact) {
    container.innerHTML = list
      .map(
        (p) => `
      <a class="post-item post-item--compact" href="?p=${encodeURIComponent(p.slug)}">
        <h3>${escapeHtml(p.title)}</h3>
        <span class="enter">进入 →</span>
      </a>`
      )
      .join('');
    return;
  }

  container.innerHTML = list
    .map(
      (p) => `
      <a class="post-item" href="?p=${encodeURIComponent(p.slug)}">
        <time>${fmtDate(p.date)}</time>
        <h3>${escapeHtml(p.title)}</h3>
        <p>${escapeHtml(p.summary || '')}</p>
      </a>`
    )
    .join('');
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/* ------------------------------------------------------------------
   加密内容（浏览器端解密）
   - 服务器上只放密文；标题永远来自 posts.json，公开可见。
   - 加密算法与 tools/lock.html 完全一致：
       文件字节 = salt(16) + iv(12) + AES-256-GCM 密文
       密钥 = PBKDF2(password, salt, 250000 次, SHA-256)
-------------------------------------------------------------------*/
async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

async function decryptData(buf, password) {
  const data = new Uint8Array(buf);
  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const ct = data.slice(28);
  const key = await deriveKey(password, salt);
  // 密码错误时 AES-GCM 会抛异常（认证失败），据此判断“密码不对”
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
}

function lockFormHtml(actionLabel) {
  return (
    '<form class="lock">' +
    '<p class="lock-label">🔒 ' + escapeHtml(actionLabel) + '需要密码</p>' +
    '<div class="lock-row">' +
    '<input type="password" class="lock-input" placeholder="输入密码" autocomplete="off" />' +
    '<button type="submit" class="lock-btn">解锁</button>' +
    '</div>' +
    '<p class="lock-msg"></p>' +
    '</form>'
  );
}

/* 给一个解锁表单接线：提交时下载密文 `url`，用输入的密码解密，
   把解密后的字节交给 onOk（返回一个 DOM 节点用来替换表单）。 */
function wireLockForm(form, url, onOk) {
  if (!form) return;
  const input = form.querySelector('.lock-input');
  const msg = form.querySelector('.lock-msg');
  const btn = form.querySelector('.lock-btn');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const pw = input.value;
    if (!pw) return;
    btn.disabled = true;
    msg.textContent = '解锁中…';
    try {
      const buf = await fetch(url, { cache: 'no-cache' }).then((r) => {
        if (!r.ok) throw new Error('fetch ' + r.status);
        return r.arrayBuffer();
      });
      const plain = await decryptData(buf, pw);
      const node = await onOk(plain);
      form.replaceWith(node);
    } catch (err) {
      msg.textContent = '密码不对，或文件加载失败。';
      btn.disabled = false;
      console.error(err);
    }
  });
}

/* 把 <div class="locked-audio" data-src="xxx.enc"> 占位符变成一个密码门，
   输对密码后在浏览器里解密并播放（服务器上从没有可播放的原文件）。 */
function initLockedAudios(root) {
  root.querySelectorAll('.locked-audio').forEach((el) => {
    const src = el.getAttribute('data-src');
    if (!src) return;
    el.innerHTML = lockFormHtml('收听录音');
    wireLockForm(el.querySelector('.lock'), src, async (plainBuf) => {
      const blob = new Blob([plainBuf], { type: 'audio/mp4' });
      const audio = document.createElement('audio');
      audio.controls = true;
      audio.style.width = '100%';
      audio.src = URL.createObjectURL(blob);
      audio.play().catch(() => {});
      return audio;
    });
  });
}


function parseTimestamp(value) {
  const parts = String(value).split(':').map(Number);
  if (parts.length === 2) return parts[0] * 60 + parts[1];
  if (parts.length === 3) return parts[0] * 3600 + parts[1] * 60 + parts[2];
  return 0;
}

function fmtCaptionTime(seconds) {
  const safe = Math.max(0, Math.floor(seconds || 0));
  const minutes = Math.floor(safe / 60);
  const remainder = safe % 60;
  return String(minutes).padStart(2, '0') + ':' + String(remainder).padStart(2, '0');
}

function parseTimedTranscript(source, duration) {
  const blocks = [];
  const lines = String(source).replace(/\r\n/g, '\n').split('\n');
  let current = null;

  lines.forEach((rawLine) => {
    const line = rawLine.trim();
    if (!line) return;

    if (/^\d{2}:\d{2}(?::\d{2})?$/.test(line)) {
      if (current) blocks.push(current);
      current = { start: parseTimestamp(line), text: [] };
    } else if (current) {
      current.text.push(line);
    }
  });

  if (current) blocks.push(current);

  const pieces = [];
  blocks.forEach((block, index) => {
    const next = blocks[index + 1];
    const end = next ? next.start : duration || block.start + 8;
    pieces.push(...expandTranscriptBlock(block, end));
  });

  return pieces.map((piece, index) => ({
    id: index + 1,
    start: Number(piece.start.toFixed(2)),
    end: Number(piece.end.toFixed(2)),
    startLabel: fmtCaptionTime(piece.start),
    text: piece.text,
  }));
}

function splitTextPieces(text) {
  return text
    .replace(/\s+/g, ' ')
    .trim()
    .split(/(?<=[。！？!?；;，,])\s*/)
    .map((piece) => piece.trim())
    .filter(Boolean);
}

function chunkTextForCaptions(text) {
  const pieces = splitTextPieces(text);
  const chunks = [];
  let current = '';

  pieces.forEach((piece) => {
    const next = current ? current + piece : piece;
    if (current && next.length > 68) {
      chunks.push(current);
      current = piece;
    } else {
      current = next;
    }

    if (current.length >= 44) {
      chunks.push(current);
      current = '';
    }
  });

  if (current) {
    if (chunks.length && current.length < 18) {
      chunks[chunks.length - 1] += current;
    } else {
      chunks.push(current);
    }
  }

  return chunks.length ? chunks : [text.trim()];
}

function expandTranscriptBlock(block, end) {
  const text = block.text.join(' ').replace(/\s+/g, ' ').trim();
  const chunks = chunkTextForCaptions(text);
  const totalChars = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  let cursor = block.start;

  return chunks.map((chunk, index) => {
    const isLast = index === chunks.length - 1;
    const duration = totalChars ? ((end - block.start) * chunk.length) / totalChars : 0;
    const next = isLast ? end : Math.min(end, cursor + Math.max(2.2, duration));
    const segment = { start: cursor, end: next, text: chunk };
    cursor = next;
    return segment;
  });
}

function findCaptionIndex(segments, time) {
  const index = segments.findIndex((segment) => time >= segment.start && time < segment.end);
  if (index !== -1) return index;
  if (segments.length && time >= segments[segments.length - 1].end) return segments.length - 1;
  return 0;
}

function captionWindowFor(segments, time) {
  const currentIndex = findCaptionIndex(segments, time);
  const fromIndex = Math.max(0, currentIndex - 1);
  const toIndex = Math.min(segments.length - 1, currentIndex + 4);
  return {
    currentId: segments[currentIndex] && segments[currentIndex].id,
    items: segments.slice(fromIndex, toIndex + 1),
  };
}

function initAudioTranscripts(root) {
  root.querySelectorAll('.audio-transcript').forEach(async (mount) => {
    const audioSrc = mount.getAttribute('data-audio');
    const transcriptSrc = mount.getAttribute('data-transcript');
    if (!audioSrc || !transcriptSrc) return;

    mount.innerHTML =
      '<div class="audio-card">' +
      '<audio controls controlsList="nodownload noremoteplayback" disableRemotePlayback preload="metadata" src="' + escapeHtml(audioSrc) + '"></audio>' +
      '</div>' +
      '<div class="below-audio-actions">' +
      '<button class="transcript-toggle" type="button" aria-expanded="false">显示文稿</button>' +
      '</div>' +
      '<div class="caption-window is-hidden" aria-live="polite" hidden><p class="empty">文稿会按当前播放位置出现。</p></div>';

    const audio = mount.querySelector('audio');
    const toggle = mount.querySelector('.transcript-toggle');
    const captionWindow = mount.querySelector('.caption-window');
    let transcriptOpen = false;
    let segments = [];
    let lastLoadedSecond = -1;

    audio.addEventListener('contextmenu', (event) => event.preventDefault());
    audio.addEventListener('loadedmetadata', async () => {
      try {
        const source = await fetch(transcriptSrc, { cache: 'no-cache' }).then((res) => {
          if (!res.ok) throw new Error('transcript ' + res.status);
          return res.text();
        });
        segments = parseTimedTranscript(source, audio.duration || 0);
        if (transcriptOpen) renderAudioCaptions(captionWindow, segments, audio.currentTime || 0);
      } catch (error) {
        captionWindow.innerHTML = '<p class="empty">文稿加载失败。</p>';
        console.error(error);
      }
    });

    function refreshCaptions() {
      if (!transcriptOpen || !segments.length) return;
      renderAudioCaptions(captionWindow, segments, audio.currentTime || 0);
    }

    toggle.addEventListener('click', () => {
      transcriptOpen = !transcriptOpen;
      captionWindow.hidden = !transcriptOpen;
      captionWindow.classList.toggle('is-hidden', !transcriptOpen);
      toggle.textContent = transcriptOpen ? '隐藏文稿' : '显示文稿';
      toggle.setAttribute('aria-expanded', String(transcriptOpen));
      refreshCaptions();
    });

    audio.addEventListener('timeupdate', () => {
      const second = Math.floor(audio.currentTime || 0);
      if (second !== lastLoadedSecond) {
        lastLoadedSecond = second;
        refreshCaptions();
      }
    });

    audio.addEventListener('seeked', refreshCaptions);

    captionWindow.addEventListener('click', (event) => {
      const target = event.target.closest('[data-time]');
      if (!target) return;
      audio.currentTime = Number(target.dataset.time);
      refreshCaptions();
      audio.play().catch(() => {});
    });
  });
}

function renderAudioCaptions(container, segments, time) {
  const win = captionWindowFor(segments, time);
  if (!win.items.length) {
    container.innerHTML = '<p class="empty">这一小段暂时没有字幕。</p>';
    return;
  }

  container.innerHTML = win.items
    .map((item) => {
      const active = item.id === win.currentId;
      return (
        '<article class="caption-line ' + (active ? 'is-active' : '') + '" data-time="' + item.start + '">' +
        '<button class="time-link" type="button" data-time="' + item.start + '">' + item.startLabel + '</button>' +
        '<p>' + escapeHtml(item.text) + '</p>' +
        '</article>'
      );
    })
    .join('');
}


/* Render a single post given its slug */
async function renderArticle(slug) {
  const posts = await loadPosts();
  const post = posts.find((p) => p.slug === slug);
  const listView = document.getElementById('list-view');
  const artView = document.getElementById('article-view');
  const bodyEl = document.getElementById('article-body');

  listView.style.display = 'none';
  artView.style.display = 'block';

  if (!post) {
    document.getElementById('article-meta').textContent = '';
    bodyEl.innerHTML = '<h1>找不到这篇日志</h1><p>可能链接过期了。</p>';
    return;
  }

  document.title = post.title + ' · Somethin Hapi';
  document.getElementById('article-meta').textContent = fmtDate(post.date);

  // 标题永远公开（来自 posts.json），哪怕正文被加密
  const titleHtml = '<h1>' + escapeHtml(post.title) + '</h1>';

  // 整篇加密：posts.json 里标了 "locked": true，file 指向 .enc 密文
  if (post.locked) {
    bodyEl.innerHTML = titleHtml + lockFormHtml('查看这篇日志');
    wireLockForm(bodyEl.querySelector('.lock'), 'posts/' + post.file, async (plainBuf) => {
      const md = new TextDecoder().decode(plainBuf);
      const holder = document.createElement('div');
      holder.innerHTML = marked.parse(md);
      initLockedAudios(holder); // 万一整篇里还嵌了单独锁的音频
      initAudioTranscripts(holder);
      return holder;
    });
    window.scrollTo(0, 0);
    return;
  }

  // 普通（未锁）日志：正常渲染 markdown，正文里若有 locked-audio 再单独接线
  try {
    const res = await fetch('posts/' + post.file, { cache: 'no-cache' });
    if (!res.ok) throw new Error(res.status);
    const md = await res.text();
    bodyEl.innerHTML = titleHtml + marked.parse(md);
    initLockedAudios(bodyEl);
    initAudioTranscripts(bodyEl);
  } catch (e) {
    bodyEl.innerHTML = titleHtml + '<p>正文加载失败。</p>';
    console.error(e);
  }
  window.scrollTo(0, 0);
}

/* Entry point for blog.html */
function bootBlogPage() {
  const params = new URLSearchParams(location.search);
  const slug = params.get('p');
  if (slug) {
    renderArticle(slug);
  } else {
    renderPostList(document.getElementById('post-list'));
  }
}

// expose for index.html (homepage)
window.renderPostList = renderPostList;
window.bootBlogPage = bootBlogPage;
