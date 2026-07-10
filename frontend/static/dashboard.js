$(document).ready(async function(){
    await getIocCount();
});

async function getIocCount(){
    const response = await AjaxCallWithoutParm("/get_ioc_overview/");
    $("#emailCount").text(response.email_count);
}