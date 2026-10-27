(function () {
  var print = document.getElementById('print-handover');
  if (print) print.addEventListener('click', function () { window.print(); });
  var form = document.getElementById('handover-form');
  if (!form) return;
  var publish = document.getElementById('publish-handover');
  var revoke = document.getElementById('revoke-handover');
  var note = document.getElementById('handover-note');
  var link = document.getElementById('handover-link');
  var view = document.getElementById('view-handover');
  var result = document.getElementById('handover-result');
  function request(action) {
    publish.disabled = true; revoke.disabled = true;
    note.textContent = action === 'publish' ? 'Creating your limited summary…' : 'Disabling the live link…';
    fetch('/api/scan/' + encodeURIComponent(form.dataset.scan) + '/handover', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({action:action, token:form.dataset.token,
        confirmed:document.getElementById('handover-consent').checked,
        include_target:document.getElementById('handover-target').checked})
    }).then(function(r) { return r.json().then(function(d) { if(!r.ok) throw new Error(d.error || 'Please try again.'); return d; }); })
      .then(function(d) {
        if(action === 'publish') {
          link.value=d.url; view.href=d.url; result.classList.remove('hidden');
          note.textContent='Link ready. Anyone with it can view this limited summary. Expires: ' + d.expires_at + '. No email was sent.';
        } else {
          link.value=''; view.removeAttribute('href'); result.classList.add('hidden');
          note.textContent='Live link disabled. Copies already saved by others cannot be recalled.';
        }
      }).catch(function(e) { note.textContent=e.message || 'Network error. Please try again.'; })
      .then(function() { publish.disabled=false; revoke.disabled=false; });
  }
  form.addEventListener('submit', function(e) { e.preventDefault(); if(form.reportValidity()) request('publish'); });
  revoke.addEventListener('click', function() { request('revoke'); });
})();
