function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

async function AjaxCall(url , data){
    const parm = JSON.stringify(data);
    try{
        let response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken' : getCookie('csrftoken')
            },
            body: parm,
            credentials: 'include'
        });
        let result = await response.json();
        return result;
    }
    catch(error){
        console.log("Error while making api request");
    }
}
async function AjaxCallWithoutParm(url){
    try{
        let response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken' : getCookie('csrftoken')
            },
            credentials: 'include'
        });
        let result = await response.json();
        return result;
    }
    catch(error){
        console.log("Error while making api request");
    }
}

async function UserValidation(role){
    let data = await AjaxCallWithoutParm("/getLoginData");
    if(data["id"] == 0 || data['role'] != role){
        alert("You are not logged in as proper role!")
        return false;
    }
    else{
        return true;
    }
}
