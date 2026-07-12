$(document).ready(async function(){
    await renderDashboard();
});

async function renderDashboard(){
    let response = {}
    if(window.location.pathname == "/analystPage/"){
        response = await AjaxCallWithoutParm("/dashboard_data/");
    }
    else{
        const userData = await AjaxCallWithoutParm("/getCurrentUserInfo/");
        const parm = {
            email: userData.email
        }
        response = await AjaxCall("/dashboard_data/", parm);
        $("#malReceiveDiv").hide();
    }
    $("#emailCount").text(response.email_count);
    $("#maliciousEmailCount").text(response.malicious_email_count);
    $("#meanRiskScore").text(fixedFloat(response.avg_risk_scores.Overall));
    $("#analystNotesCount").text(response.no_notes_count);
    RenderPhishingPie(response.phishing_type_count);
    RenderBarChart(response.verdict_count);
    RenderTopMaliciousSender(response.malicious_sender_count);
    RenderTopMaliciousReceiver(response.top_mal_receiver_count);
}

function RenderPhishingPie(data){
    let pieDom = document.getElementById("phishingDiv");
    let pieChart = echarts.init(pieDom);
    let option;
    let pieData = [];

    for (const [key, value] of Object.entries(data)) {
        pieData.push({value: value, name: key});
    }

    option = {
        tooltip:{
            trigger: "item",
        },
        series : [
            {
                type: "pie",
                stillShowZeroSum: false,
                data: pieData,
            }
        ]
    };
    option && pieChart.setOption(option);
}

function RenderBarChart(data){
    let barDom = document.getElementById("verdictDiv");
    let barChart = echarts.init(barDom);
    let option;
    let barData = [];

    for (const [key, value] of Object.entries(data)) {
        barData.push({value: value, name: key});
    }

    option = {
        tooltip:{
            trigger: "item",
        },
        series : [
            {
                type: "pie",
                stillShowZeroSum: false,
                data: barData,
            }
        ]
    };
    option && barChart.setOption(option);
}


function RenderTopMaliciousSender(data){
    let html = ``;
    let index = 0;
    for(const [key, value] of Object.entries(data)) {
        html += `
            <tr>
                <td class="ps-3">${index + 1}</td>
                <td class="ps-3">${key}</td>
                <td class="ps-3">${value}</td>
            </tr>
        `;
        index++;
    }

    $("#topMaliciousSenders").empty().append(html);
}

function RenderTopMaliciousReceiver(data){
    let html = ``;
    let index = 0;
    for(const [key, value] of Object.entries(data)) {
        html += `
            <tr>
                <td class="ps-3">${index + 1}</td>
                <td class="ps-3">${key}</td>
                <td class="ps-3">${value}</td>
            </tr>
        `;
        index++;
    }

    $("#topMaliciousReceivers").empty().append(html);
}

$("#fetchEmail").on("click", async function(){
    const response = await AjaxCallWithoutParm("/analyze_email/");
    if(response.status == 200){
        await renderDashboard();
        toastr.success("Email fetch completed successfully.");
    } else {
        toastr.error("Error fetching emails. Please try again later.");
    }
});