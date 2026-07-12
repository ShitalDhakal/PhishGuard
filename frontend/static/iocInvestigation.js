$(document).ready(async function(){
    await RenderUserFilter();
    await getIOCData();
});

async function getIOCData(){
    const parm ={
        ioc_type: $("#ioc_type").val(),
        verdict: $("#ioc_verdict").val(),
        search_text: $("#ioc_search_text").val(),
        email: $("#userFilter").val()
    }
    const response = await AjaxCall("/get_ioc_overview/", parm);
    let tableHtml = ``;
    response.data.forEach((item) => {
        tableHtml += `
            <tr>
                <td>${item.ioc_type}</td>
                <td>${item.value}</td>
                <td>${String(item.is_malicious || "Unscanned")}</td>
                <td>${item.file_hash || ""}</td>
                <td>${item.recurring_iocs}</td>
                <td></td>
            </tr>
        `;
    });

    $("#ioc_table > tbody").html(tableHtml);
}

$("#ioc_search_btn").click(async function(){
    await getIOCData();
});

async function RenderUserFilter(){
    const response = await AjaxCallWithoutParm("/get_all_users/");
    let userHtml = '<option value="all">All</option>';
    response.data.forEach(user => {
        if(user.role == "employee"){
            userHtml += `<option value="${user.email}">${user.username} - ${user.email}</option>`;
        }
    });
    $('#userFilter').html(userHtml);
}