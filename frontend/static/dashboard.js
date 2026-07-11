$(document).ready(async function(){
    await renderDashboard();
});

async function renderDashboard(){
    const response = await AjaxCallWithoutParm("/dashboard_data/");
    $("#emailCount").text(response.email_count);
    $("#maliciousEmailCount").text(response.malicious_email_count);
    $("#meanRiskScore").text(fixedFloat(response.avg_risk_scores.Overall));
    $("#analystNotesCount").text(response.no_notes_count);
    RenderPhishingPie(response.phishing_type_count);
    RenderBarChart(response.verdict_count);
    RenderTopMaliciousSender(response.malicious_sender_count);
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