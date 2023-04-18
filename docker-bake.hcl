
group "default" {
  targets = ["server", "console"]
}

target "wrapped" {
  context = "./docker-riscv"
  target = "wrapped-stage"
  contexts = {
    dapp = "target:dapp"
  }
}

target "fs" {
  context = "./docker-riscv"
  target  = "fs-stage"
  contexts = {
    wrapped = "target:wrapped"
  }
}

target "server" {
  context = "./docker-riscv"
  target  = "server-stage"
  contexts = {
    fs = "target:fs"
  }
}

target "console" {
  context = "./docker-riscv"
  target  = "console-stage"
  contexts = {
    fs = "target:fs"
  }
}

target "machine" {
  context = "./docker-riscv"
  target  = "machine-stage"
  contexts = {
    fs = "target:fs"
  }
}


