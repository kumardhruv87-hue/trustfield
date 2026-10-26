(function(){
  var form=document.getElementById("scan-form"), input=document.getElementById("scan-target"),
      btn=document.getElementById("scan-btn"), status=document.getElementById("scan-status");
  if(!form) return;
  var q=new URLSearchParams(location.search);
  var utm={source:q.get("utm_source")||"",medium:q.get("utm_medium")||"",campaign:q.get("utm_campaign")||""};
  form.addEventListener("submit",function(e){
    e.preventDefault();
    var consent=document.getElementById("scan-consent");
    if(!consent || !consent.checked){form.reportValidity();return;}
    var target=(input.value||"").trim();
    if(!target){input.focus();return;}
    var kind="url";
    if(/^(?:www\.)?github\.com\//i.test(target)) target="https://"+target;
    if(/^https?:\/\/(?:www\.)?github\.com\/[^/]+\/[^/]+/i.test(target) || /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(target) && target.split("/")[0].indexOf(".")===-1) kind="repo";
    if(kind==="url" && !/^https?:\/\//i.test(target)) target="https://"+target;
    btn.disabled=true; status.hidden=false; status.textContent="Checking your public app or repository…";
    fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({kind:kind,target:target,consent:consent.checked,utm:utm,source:utm.source||"direct"})})
    .then(function(r){return r.json().then(function(d){return {ok:r.ok,data:d};});})
    .then(function(out){
      if(out.ok && out.data && out.data.id){ status.textContent="Scan ready — opening your results…"; location.href="/r/"+out.data.id; }
      else { btn.disabled=false; status.textContent=(out.data&&out.data.error)||"Scan failed. Try again."; }
    })
    .catch(function(){btn.disabled=false;status.textContent="Network error. Try again.";});
  });
})();
