package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/nats-io/nats"
)

var natsIp string

func init() {
	flag.StringVar(&natsIp, "nats", "", "nats IP")
}

const setupPs1 = `param (
   [switch]$quiet = $false,
   [switch]$version = $false
)

if ($version) {
    Write-Host "Version 0.122"
    exit
}

$Error.Clear()

Configuration CFWindows {
  Node "localhost" {

    WindowsFeature IISWebServer {
      Ensure = "Present"
        Name = "Web-Webserver"
    }
    WindowsFeature WebSockets {
      Ensure = "Present"
        Name = "Web-WebSockets"
    }
    WindowsFeature WebServerSupport {
      Ensure = "Present"
        Name = "AS-Web-Support"
    }
    WindowsFeature DotNet {
      Ensure = "Present"
        Name = "AS-NET-Framework"
    }
    WindowsFeature HostableWebCore {
      Ensure = "Present"
        Name = "Web-WHC"
    }

    WindowsFeature ASPClassic {
      Ensure = "Present"
      Name = "Web-ASP"
    }

    Script SetupDNS {
      SetScript = {
        [array]$routeable_interfaces = Get-WmiObject Win32_NetworkAdapterConfiguration | Where { $_.IpAddress -AND ($_.IpAddress | Where { $addr = [Net.IPAddress] $_; $addr.AddressFamily -eq "InterNetwork" -AND ($addr.address -BAND ([Net.IPAddress] "255.255.0.0").address) -ne ([Net.IPAddress] "169.254.0.0").address }) }
        $ifindex = $routeable_interfaces[0].Index
        $interface = (Get-WmiObject Win32_NetworkAdapter | Where { $_.DeviceID -eq $ifindex }).netconnectionid

        $currentDNS = ((Get-DnsClientServerAddress -InterfaceAlias $interface) | where { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }).ServerAddresses
        $newDNS = @("127.0.0.1") + $currentDNS
        Set-DnsClientServerAddress -InterfaceAlias $interface -ServerAddresses ($newDNS -join ",")
      }
      GetScript = {
        return $false
      }
      TestScript = {
        [array]$routeable_interfaces = Get-WmiObject Win32_NetworkAdapterConfiguration | Where { $_.IpAddress -AND ($_.IpAddress | Where { $addr = [Net.IPAddress] $_; $addr.AddressFamily -eq "InterNetwork" -AND ($addr.address -BAND ([Net.IPAddress] "255.255.0.0").address) -ne ([Net.IPAddress] "169.254.0.0").address }) }
        $ifindex = $routeable_interfaces[0].Index
        $interface = (Get-WmiObject Win32_NetworkAdapter | Where { $_.DeviceID -eq $ifindex }).netconnectionid

        if((Get-DnsClientServerAddress -InterfaceAlias $interface -AddressFamily ipv4 -ErrorAction Stop).ServerAddresses[0] -eq "127.0.0.1")
        {
          Write-Verbose -Message "DNS Servers are set correctly."
          return $true
        }
        else
        {
          Write-Verbose -Message "DNS Servers not yet correct."
          return $false
        }
      }
    }

    Script ClearDNSCache
    {
        SetScript = {
            Clear-DnsClientCache
        }
        GetScript = {
            Get-DnsClientCache
        }
        TestScript = {
            @(Get-DnsClientCache).Count -eq 0
        }
    }

    Registry DisableDNSNegativeCache
    {
        Ensure = "Present"
        Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        ValueName = "MaxNegativeCacheTtl"
        ValueType = "DWord"
        ValueData = "0"
    }

    Script EnableDiskQuota
    {
      SetScript = {
        fsutil quota enforce C:
      }
      GetScript = {
        fsutil quota query C:
      }
      TestScript = {
        $query = "select * from Win32_QuotaSetting where VolumePath='C:\\'"
        return @(Get-WmiObject -query $query).State -eq 2
      }
    }

    Registry IncreaseDesktopHeapForServices
    {
        Ensure = "Present"
        Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems"
        ValueName = "Windows"
        ValueType = "ExpandString"
        ValueData = "%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,20480 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16"
    }

    Script SetupFirewall
    {
      TestScript = {
        $anyFirewallsDisabled = !!(Get-NetFirewallProfile -All | Where-Object { $_.Enabled -eq "False" })
        $adminRuleMissing = !(Get-NetFirewallRule -Name CFAllowAdmins -ErrorAction Ignore)
        Write-Verbose "anyFirewallsDisabled: $anyFirewallsDisabled"
        Write-Verbose "adminRuleMissing: $adminRuleMissing"
        if ($anyFirewallsDisabled -or $adminRuleMissing)
        {
          return $false
        }
        else {
          return $true
        }
      }
      SetScript = {
        $admins = New-Object System.Security.Principal.NTAccount("Administrators")
        $adminsSid = $admins.Translate([System.Security.Principal.SecurityIdentifier])

        $LocalUser = "D:(A;;CC;;;$adminsSid)"
        $otherAdmins = Get-WmiObject win32_groupuser | 
          Where-Object { $_.GroupComponent -match 'administrators' } |
          ForEach-Object { [wmi]$_.PartComponent }

        foreach($admin in $otherAdmins)
        {
          $ntAccount = New-Object System.Security.Principal.NTAccount($admin.Name)
          $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
          $LocalUser = $LocalUser + "(A;;CC;;;$sid)"
        }
        New-NetFirewallRule -Name CFAllowAdmins -DisplayName "Allow admins" -Description "Allow admin users" -RemotePort Any -LocalPort Any -LocalAddress Any -RemoteAddress Any -Enabled True -Profile Any -Action Allow -Direction Outbound -LocalUser $LocalUser

        Set-NetFirewallProfile -All -DefaultInboundAction Allow -DefaultOutboundAction Block -Enabled True
      }
      GetScript = { Get-NetFirewallProfile }
    }
  }
}

if($PSVersionTable.PSVersion.Major -lt 4) {
  $shell = New-Object -ComObject Wscript.Shell
  $shell.Popup("You must be running Powershell version 4 or greater", 5, "Invalid Powershell version", 0x30)
  echo "You must be running Powershell version 4 or greater"
  exit(-1)
}

if (![bool](Test-WSMan -ErrorAction SilentlyContinue)) {
  Enable-PSRemoting -Force
}
Install-WindowsFeature DSC-Service
CFWindows
Start-DscConfiguration -Wait -Path .\CFWindows -Force -Verbose

if ($Error) {
    Write-Host "Error summary:"
    foreach($ErrorMessage in $Error)
    {
      Write-Host $ErrorMessage
    }
	}
`

func main() {
	flag.Parse()
	fmt.Println(natsIp)
	nc, err := nats.Connect(fmt.Sprintf("nats://%s:4222", natsIp))
	if err != nil {
		log.Fatal(err)
	}
	write := func(msg string) {
		filename := "C:\\tmp\\file.txt"
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if _, err = f.WriteString(msg); err != nil {
			panic(err)
		}
	}
	receivedCounter := 0
	respondedCounter := 0
	nc.Subscribe("bar", func(m *nats.Msg) {
		fmt.Println("Got bar", string(m.Data))
		receivedCounter++
		msg := fmt.Sprintf("%s- received: %d", string(m.Data), receivedCounter)
		write(msg)
	})
	nc.Subscribe("foo", func(m *nats.Msg) {
		respondedCounter++
		msg := `echo "Started %s $(date)"; sleep 2; echo "Stopped %s $(date)"`
		out, err := exec.Command("powershell", "-c", fmt.Sprintf(msg, "hello", "hello")).Output()
		if err != nil {
			log.Fatal(err)
		}
		nc.Publish("bar", []byte(fmt.Sprintf("%s-responded %d", out, respondedCounter)))
	})
	nc.Flush()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	sleeper := make(chan bool, 1)
	go func() {
		for {
			time.Sleep(5 * time.Second)
			sleeper <- true
		}
	}()
	go func() {
		for {
			time.Sleep(1 * time.Second)
			nc.Publish("foo", []byte("Hello World"))
		}
	}()

	for {
		fmt.Println("Looping...")
		select {
		case s := <-c:
			fmt.Println("Got signal:", s)
			nc.Close()
			return
		case <-sleeper:
			fmt.Println("Staring to sleep, counter=", respondedCounter)
			out, err := exec.Command("powershell", "-c", setupPs1).Output()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Slept for 5 seconds", string(out))
		}
	}

}
