function allowDrop(ev) {
    console.log("allowDrop");
  ev.preventDefault();

  document.querySelectorAll(".assignment-list.over").forEach(box =>
    box.addEventListener("dragleave", () => box.classList.remove("over"))
  );

  ev.currentTarget.classList.add("over");
}

function drag(ev) {
    console.log("drag");
  ev.dataTransfer.setData("text", ev.target.id);
}

function drop(ev) {
    console.log("drop");
  ev.preventDefault();
  const data = ev.dataTransfer.getData("text");
  const dragged = document.getElementById(data);
  ev.currentTarget.appendChild(dragged);
  ev.currentTarget.classList.remove("over");

  document.querySelectorAll(".assignment-list.over").forEach(box =>
    box.addEventListener("dragleave", () => box.classList.remove("over"))
  );
}
