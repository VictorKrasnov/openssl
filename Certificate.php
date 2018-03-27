<?php

namespace Webslon\Library\OpenSSL;

class Certificate
{
    private $fileName;
    private $tmpFileName = null;
    private $loaded = false;
    private $type = null;

    private $subject = null;
    private $issuer = null;
    private $dates = null;
    private $hash = null;
    private $fingerprint = null;

    private $subjectConverted = null;
    private $issuerConverted = null;
    private $datesConverted = null;
    private $hashConverted = null;
    private $fingerprintConverted = null;

    public function __construct($fileName)
    {
        $this->fileName = $fileName;
        $this->load();
    }

    public function __destruct()
    {
        if (!is_null($this->tmpFileName) && file_exists($this->tmpFileName)) {
            unlink($this->tmpFileName);
        }
    }

    public function getAll()
    {
        $arResult = array();
        $arResult["loaded"] = $this->loaded;
        $arResult["fileName"] = $this->fileName;
        $arResult["tmpFileName"] = $this->tmpFileName;

        if ($this->loaded) {
            $arResult["isValid"] = $this->isValid();
            $arResult["subject"] = $this->getSubject();
            $arResult["issuer"] = $this->getIssuer();
            $arResult["dates"] = $this->getDates();
            $arResult["hash"] = $this->getHash();
            $arResult["fingerprint"] = $this->getFingerprint();
        }

        return $arResult;
    }

    public function isValid()
    {
        $dates = $this->getDates();
        if (is_null($dates)) return false;

        foreach ($dates as $key => $value) {
            if ($key === "notBefore") {
                $date = strtotime($value);
                if (time() < $date) {
                    return false;
                }
            } elseif ($key === "notAfter") {
                $date = strtotime($value);
                if (time() > $date) {
                    return false;
                }
            } else {
                // TODO: Что делать, если натыкаемся на неизвестный ключ?
                return false;
            }
        }
        return true;
    }

    public function getSubject()
    {
        if (is_null($this->subjectConverted)) {
            $data = $this->subject;
            $this->subjectConverted = $this->organizationToArray($data);
        }
        return $this->subjectConverted;
    }

    public function getIssuer()
    {
        if (is_null($this->issuerConverted)) {
            $data = $this->issuer;
            $this->issuerConverted = $this->organizationToArray($data);
        }
        return $this->issuerConverted;
    }

    public function getDates()
    {
        if (is_null($this->datesConverted)) {
            if (!is_null($this->dates)) {
                $data = $this->dates;
                $arDates = explode("\n", $data);
                $arResult = array();
                foreach ($arDates as $item) {
                    $arItem = explode("=", $item);
                    if (count($arItem) < 2) continue;

                    $key = array_shift($arItem);
                    $value = trim(implode("=", $arItem));

                    $arResult[$key] = $value;
                }
                $this->datesConverted = $arResult;
            }
        }
        return $this->datesConverted;
    }

    public function getHash()
    {
        if (is_null($this->hashConverted)) {
            if (!is_null($this->hash)) {
                $this->hashConverted = trim($this->hash);
            }
        }
        return $this->hashConverted;
    }

    public function getFingerprint()
    {
        if (is_null($this->fingerprintConverted)) {
            if (!is_null($this->fingerprint)) {
                $this->fingerprintConverted = trim($this->fingerprint);
            }
        }
        return $this->fingerprintConverted;
    }

    private function organizationToArray($data)
    {
        if (is_null($data)) {
            return null;
        }

        $data = static::convertXcodesToText($data);
        $items = explode("/", $data);
        $arResult = array();
        $arWebslon = array();

        # http://www.2410000.ru/p_45_spravochnik_oid_oid__najti_oid_oid_perechen_oid_oid_obektnyj_identifikator_oid_oid_object_identifier.html
        $webslonMap = array(
            "1.2.643.100.1" => "OGRN",
            "1.2.643.3.131.1.1" => "INN",
            "1.2.643.100.3" => "SNILS",
            "1.2.643.100.5" => "OGRNIP",
            "1.2.643.3.141.1.1" => "RNS_FSS",
            "1.2.643.3.141.1.2" => "KP_FSS",
            "2.5.4.65" => "PSEUDONYM",
            "2.5.4.16" => "POST_ADDRESS",
        );

        foreach ($items as &$item) {
            $arItem = explode("=", $item);
            if (count($arItem) < 2) continue;

            $key = array_shift($arItem);
            $value = trim(implode("=", $arItem));

            if ($key === "subject" && !$value) continue;
            if ($key === "issuer" && !$value) continue;

            $arResult[$key] = $value;

            if (array_key_exists($key, $webslonMap)) {
                if ($webslonMap[$key] == "INN") {
                    $value = ltrim($value, "0");
                }
                $arWebslon[$webslonMap[$key]] = $value;
            }
        }

        $arResult["webslon"] = $arWebslon;

        return $arResult;
    }

    private function load()
    {
        if (!is_null($this->tmpFileName)) {
            $fileName = $this->tmpFileName;
        } else {
            $fileName = $this->fileName;
        }

        // PEM encoded certificate
        $data = shell_exec("openssl x509 -noout -in $fileName -subject 2>&1");
        if (strpos($data, "unable to load certificate") === false) { // это PEM
            $this->type = "PEM";
            $this->subject = $data;
        } else {

            // DER encoded Certificate
            $data = shell_exec("openssl x509 -inform DER -noout -in $fileName -subject 2>&1");
            if (strpos($data, "unable to load certificate") === false) { // это DER
                $this->type = "DER";
                $this->subject = $data;
            } else {

                // p7b certificate
                if (is_null($this->tmpFileName)) {
                    $data = shell_exec("openssl pkcs7 -inform DER -outform PEM -in $fileName -print_certs 2>&1");
                    if (strpos($data, "unable to load PKCS7 object") === false) { // получилось разобрать pkcs7
                        $this->tmpFileName = tempnam("/tmp", "pkcs7");
                        file_put_contents($this->tmpFileName, $data);
                        return $this->load();
                    }
                }
            }

        }

        switch ($this->type) {
            case "PEM":
                $sshCommand = "openssl x509 -noout -in $fileName";
                break;
            case "DER":
                $sshCommand = "openssl x509 -inform DER -noout -in $fileName";
                break;
            default:
                return false;
        }

        $this->issuer = shell_exec("$sshCommand -issuer 2>&1");
        $this->dates = shell_exec("$sshCommand -dates 2>&1");
        $this->hash = shell_exec("$sshCommand -hash 2>&1");
        $this->fingerprint = shell_exec("$sshCommand -fingerprint 2>&1");

        $this->loaded = true;
        return true;
    }

    private function convertXcodesToText($string)
    {
        $result = preg_replace_callback("/(\\\\x)([0-9A-Fa-f]+)/u", function ($matched) {
            return chr(hexdec($matched[2]));
        }, $string);
        return $result;
    }
}