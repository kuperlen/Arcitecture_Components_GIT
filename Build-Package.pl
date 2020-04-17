#!/usr/bin/perl
#use strict;
use warnings FATAL => 'all';
use lib qw(..);
use JSON qw( );
#use JSON::MaybeXS qw(encode_json decode_json);
use JSON::MaybeXS ();

sub SaveSecret {
    my ($sec_dest, $json_repl) = @_;
    my $secret = $json_repl->{Value};
    print "Save new secret: Value $secret to $sec_dest\n";
    open (SF, '>', $sec_dest) or die $!;
    print SF $secret;
}

sub CreateSecret {
    my ($sec_type, $sec_value) = @_;
    my $secret = {
        Type => 'TextBlob',
        Value => $sec_value,
        Tags => {
            "DPE_APP_ID" => $app_id,
            "APP_ENV_NAME" => $env_name,
            "DPE_ENV_CLASS" => $env_class,
            "DPE_RELEASE_ID" => $release_id,
            "DPE_CREATED_BY" => $created_by,
        },
    };
    my $secret_json = JSON::MaybeXS::encode_json $secret;
#    print $secret_json."\n";
    return $secret_json;

}

sub AddSecret {
    my ($sec_name, $sec_orig_loc) = @_;
#    print "Add new secret: $sec_name from $sec_orig_loc\n";
    my $orig_sec = $sec_orig_loc;
    my $sec_value = do {
        open(my $sec_fh, "<:encoding(UTF-8)", $orig_sec)
            or die("Can't open $orig_sec\": $!\n");
        local $/;
        <$sec_fh>
    };
#    print "Orig_Secret: $sec_value\n";
    my $secret_json = CreateSecret($sec_type, $sec_value);
    #save the secret to DBE SM.
#    my $command = "--insecure $dpe_url/secret/$app_id-$env_name-$sec_name -H \"Authorization: Bearer $token\"";
    my $command = "--insecure $dpe_url/secret/$app_id-$env_name-$sec_name -H \"Authorization: Bearer $token\" -H \"Content-Type: application/json\" -X POST -d $secret_json";
#    print $command."\n";
    #my $response_json = `curl $command`;
    ########TEST ONLY - secret response stub#######
    my $response_stub = {
        ResponseMetadata => {
            Status          => "SUCCESS",
            RequestId       => "01ddbaee-72f2-42c1-8bcf-ab2ee50e5fc7",
        },
        Value => "-----BEGIN CERTIFICATE-----\ntesttesttesttesttesttesttsest\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ntesttesttesttesttesttesttsest\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ntesttesttesttesttesttesttsest\n-----END CERTIFICATE-----\n",
    };
    my $response_json = JSON::MaybeXS::encode_json $response_stub;
    ########TEST ONLY - secret response stub#######
#    print "ADD SECRET RESPONSE JSON: ".$response_json."\n";
    return $response_json;
}

sub RetrieveSecret{
    my ($sec_name, $sec_orig_loc, $sec_dest, $add_response) = @_;
    print "DPE_URL ".$dpe_url."; Env_Name ".$env_name."; App_id ".$app_id."; Token ".$token."; secret-name ". $sec_name."; secret-location ".$sec_orig_loc."\n";
    # perform a secret fetch, if none returned, add the secret to DBE SM.
    my $json_repl;
    if (!$add_response) {
        my $command = "--insecure $dpe_url/secret/$app_id-$env_name-$sec_name -H \"Authorization: Bearer $token\"";
#        print $command . "\n";
        #my $response = `curl $command`;
        my $response = '{"ResponseMetadata": {"Status": "FAILURE", "Error": {"Type": "SecretNotFound"}, "RequestId": "ac7e53cd-cc58-43c9-b676-23b965042a72"}}';
#        print "RETRIEVE REQUEST RESPONSE :" . $response . "\n";
        $json_repl = JSON->new->utf8->decode($response);
    } else {
        $json_repl = JSON->new->utf8->decode($add_response);
    }
    my $resp_status = $json_repl->{ResponseMetadata}->{Status};
    print "Status: ".$resp_status."\n";
    if ($resp_status eq "FAILURE") {
        $status_type = $json_repl->{ResponseMetadata}->{Error}->{Type};
        if (($status_type eq "SecretNotFound") && ($retries < $dpe_retries)) {
            $retries++;
            $add_response = AddSecret ($sec_name, $sec_orig_loc);
            RetrieveSecret($sec_name, $sec_orig_loc, $sec_dest, $add_response);
            sleep 1;
        } else {die("Failed to retrieve $sec_name from DPE_Secrets_Manager with status: $status_type $!\n");}
    } else {
        SaveSecret ($sec_dest, $json_repl);
    }
}

my $dpe_tokens = 'DPE-Tokens';
my $dpe_tokens_text = do {
    open(my $json_fh, "<:encoding(UTF-8)", $dpe_tokens)
        or die("Can't open $dpe_tokens\": $!\n");
    local $/;
    <$json_fh>
};
#print $dpe_tokens_text."\n";
my $json_tokens = JSON->new;
my $data = $json_tokens->decode($dpe_tokens_text);

local $token = $data->{DPE_TOKEN};
local $app_id = $data->{DPE_APP_ID};
local $env_name = $data->{APP_ENV_NAME};
local $env_class = $data->{DPE_ENV_CLASS};
local $release_id = $data->{DPE_RELEASE_ID};
local $created_by = $data->{DPE_CREATED_BY};
local $dpe_url = $data->{DPE_URL};
local $dpe_retries = $data->{DPE_RETRIES};
local $retries = 0;

#while ( my ($k,$v) = each %$data ) { print "$k => $v\n"; }
for ( @{$data->{secrets}} ) {
    RetrieveSecret($_->{"name"}, $_->{"origin"}, $_->{"dest"});
}
