document.addEventListener("DOMContentLoaded", function () {
    var inputFotoPerfil = document.getElementById('foto_perfil');
    inputFotoPerfil.addEventListener('change', previewImage);

    function previewImage(event) {
        var reader = new FileReader();
        reader.onload = function () {
            var preview = document.getElementById('previewImage');
            preview.src = reader.result;
        }
        reader.readAsDataURL(event.target.files[0]);
    }
});

$(document).ready(function () {
    $(".usuario-button").click(function () {
        $("#info_empleado").collapse('hide');
    });
    $(".colaborador-button").click(function () {
        $("#info_usuario").collapse('hide');
    });
});


document.addEventListener("DOMContentLoaded", function () {
    var inputFotoPerfil = document.getElementById('foto_perfil_usuario');
    inputFotoPerfil.addEventListener('change', previewImage1);

    function previewImage1(event) {
        var reader = new FileReader();
        reader.onload = function () {
            var preview = document.getElementById('previewImage1');
            preview.src = reader.result;
        }
        reader.readAsDataURL(event.target.files[0]);
    }
});

// Obtener el input de archivo y el label
const inputFile = document.getElementById('cv');
const label = document.querySelector('.custom-file-label');

// Escuchar el evento de cambio del input de archivo
inputFile.addEventListener('change', function () {
    // Obtener el nombre del archivo seleccionado
    const fileName = this.files[0].name;
    // Actualizar el texto del label con el nombre del archivo
    label.textContent = fileName;
});
