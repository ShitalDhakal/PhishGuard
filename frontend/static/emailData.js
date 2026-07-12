$(document).ready(async function(){
    await RenderUserFilter();
});

async function getEmailData(userId){
    const parm = {
        user_id: parseInt(userId) || 0
    }
    const response = await AjaxCall("/get_email_data_and_scores/", parm);

    let emailListHtml = '';
    let emailContentHtml = '';
    response.data.forEach(item => { 

        let verdictBadge = ``;
        let phishingTypeBadge = ``;

        if(item.analyzed_data.length > 0){
            let phishingType = item.analyzed_data[0].phising_type || "none";
            phishingType = phishingType.toLowerCase().trim();

            verdictBadge = `<span class="badge ${verdictBg[item.analyzed_data[0].verdict.toLowerCase().trim()]}">${item.analyzed_data[0].verdict}</span>`;
            phishingTypeBadge = `<span class="badge ${phishingTypeBg[phishingType]}">${item.analyzed_data[0].phising_type || "No Phishing"}</span>`; 
        }
        else{
            verdictBadge = `<span class="badge bg-secondary">Not Analyzed</span>`;
        }

        emailListHtml += `<a href="#email-${item.email_data.id}" class="list-group-item list-group-item-action" data-bs-toggle="list" data-emailid="${item.email_data.id}">
        <div class="row">
            <div class="col-md-8">
                <strong>${item.email_data.subject}</strong>
            </div>
            <div class="col-md-4 text-end">
                ${phishingTypeBadge}
            </div>
            <div class="col-md-12">
                <small>From: ${item.email_data.sender} | To: ${item.email_data.recipient}</small>
            </div>
            <div class="col-md-12">
                <small>Date: ${item.email_data.date}</small>
            </div>
            <div class="col-md-6">
                ${verdictBadge}
            </div>

            <div class="col-md-6 text-end">
                <span class="badge bg-info">IOC(s): ${item.iocs.length}</span>
            </div>
        </div>
        </a>`;

        emailContentHtml += `<div class="tab-pane" id="email-${item.email_data.id}" role="tabpanel">
            <div class="row">
                <div class="col-md-12">
                    <h5 class="display-6">${item.email_data.subject}</h5>
                </div>
                <div class="col-md-5">
                    <label class="form-label p-0">Verdict: </label>
                    <select class="form-select form-select-sm verdictSelect">
                        <option value="0">Safe</option>
                        <option value="50">Suspicious</option>
                        <option value="100">Malicious</option>
                    </select>
                </div>
                <div class="col-md-7 mt-4">
                    <button class="btn btn-sm btn-primary updateRiskScore" data-emailid="${item.email_data.id}">Update Risk Score</button>
                </div>
                <div class="col-md-12 mt-2">
                    <label class="form-label p-0">IOC(s): </label>
                    <table class="table table-sm table-bordered ioc-table">
                        <thead>
                            <tr>
                                <th>IOC</th>
                                <th>Type</th>
                                <th>File Hash</th>
                                <th>Malicious</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${item.iocs.map(ioc => `
                                <tr>
                                    <td>${ioc.value}</td>
                                    <td>${ioc.ioc_type}</td>
                                    <td>${ioc.file_hash || ""}</td>
                                    <td>${ioc.is_malicious}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                <div class="col-md-12">
                    ${item.email_data.body_html}
                </div>

            </div>
        </div>
        `;
    });
    $('#emailList').html(emailListHtml);
    $('#emailContent').html(emailContentHtml);
}

async function RenderUserFilter(){
    const response = await AjaxCallWithoutParm("/get_all_users/");
    let userHtml = '<option value="0">All</option>';
    response.data.forEach(user => {
        if(user.role == "employee"){
            userHtml += `<option value="${user.user_id}">${user.username} - ${user.email}</option>`;
        }
    });
    $('#userFilter').html(userHtml);
}

$("#filterBtn").on("click", async function(){
    await getEmailData($("#userFilter").val());
});

$(document).on("click", ".updateRiskScore", async function(){
    const parm = {
        email_id: parseInt($(this).attr("data-emailid")) || 0,
        risk_score: parseFloat($(this).parents(".tab-pane").find(".riskScoreInput").val()) || 0
    }
    const response = await AjaxCall("/update_risk_score/", parm);
    if(response.status == 200){
        $("#filterBtn").click();
    }
    toastr.info(response.message);
});